from flask import Flask
app=Flask(__name__)
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB = "secure_documents.db"


def connect():
    return sqlite3.connect(DB)


def setup():
    db = connect()
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            name TEXT,
            owner_id INTEGER,
            content TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            user_id INTEGER,
            document_id INTEGER,
            action TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            document_id INTEGER,
            action TEXT,
            decision TEXT,
            reason TEXT,
            timestamp TEXT
        )
    """)

    db.commit()
    db.close()


def create_user(username, password, role="user"):
    db = connect()
    db.execute(
        "INSERT INTO users VALUES (NULL, ?, ?, ?)",
        (username, generate_password_hash(password), role)
    )
    db.commit()
    db.close()


def authenticate(username, password):
    db = connect()
    user = db.execute(
        "SELECT id, password, role FROM users WHERE username=?",
        (username,)
    ).fetchone()
    db.close()

    if user and check_password_hash(user[1], password):
        return {"id": user[0], "role": user[2]}

    return None


def audit(user_id, doc_id, action, decision, reason):
    db = connect()
    db.execute("""
        INSERT INTO audit_logs
        (user_id, document_id, action, decision, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id, doc_id, action, decision,
        reason, datetime.utcnow().isoformat()
    ))
    db.commit()
    db.close()


def create_document(user, name, content):
    db = connect()
    cur = db.cursor()

    cur.execute("""
        INSERT INTO documents (name, owner_id, content)
        VALUES (?, ?, ?)
    """, (name, user["id"], content))

    doc_id = cur.lastrowid
    db.commit()
    db.close()

    return doc_id


def grant_access(owner, user_id, doc_id, action):
    db = connect()

    document = db.execute(
        "SELECT owner_id FROM documents WHERE id=?",
        (doc_id,)
    ).fetchone()

    if not document or document[0] != owner["id"]:
        db.close()
        return False

    db.execute("""
        INSERT INTO permissions (user_id, document_id, action)
        VALUES (?, ?, ?)
    """, (user_id, doc_id, action))

    db.commit()
    db.close()
    return True


def access_document(user, doc_id, action="read"):
    db = connect()

    document = db.execute("""
        SELECT id, owner_id, content
        FROM documents WHERE id=?
    """, (doc_id,)).fetchone()

    if not document:
        db.close()
        audit(user["id"], doc_id, action, "DENIED",
              "Document does not exist")
        return None

    owner_id = document[1]

    allowed = (
        user["role"] == "admin"
        or owner_id == user["id"]
    )

    if not allowed:
        allowed = db.execute("""
            SELECT 1 FROM permissions
            WHERE user_id=? AND document_id=? AND action=?
        """, (user["id"], doc_id, action)).fetchone() is not None

    db.close()

    if allowed:
        audit(user["id"], doc_id, action, "GRANTED",
              "Authorisation policy satisfied")
        return document[2]

    audit(user["id"], doc_id, action, "DENIED",
          "Insufficient permissions")
    return None


if __name__ == "__main__":
    setup()
    print("Secure Document Access System Ready")
