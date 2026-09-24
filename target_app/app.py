"""
VulnNotes - a deliberately insecure demo web app.

This is the AUDIT TARGET for the CodeAlpha Secure Code Review task. It is a
small Flask "notes" service that intentionally contains a spread of common
Python security bugs so a static analyzer (bandit) and a manual reviewer have
something real to find. DO NOT deploy this anywhere.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

# --- config -----------------------------------------------------------------
# Hardcoded credentials committed to source control.
DB_PATH = "notes.db"
ADMIN_PASSWORD = "admin123"                 # hardcoded secret
API_TOKEN = "sk_live_9f8a7b6c5d4e3f2a1b0c"  # looks like a real key


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Weak password hashing (MD5, unsalted).
    hashed = hashlib.md5(password.encode()).hexdigest()

    # SQL injection: user input concatenated straight into the query.
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s' AND pw = '%s'" % (username, hashed)
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return "ok" if row else "denied"


@app.route("/notes")
def notes():
    # SQL injection again, via .format().
    note_id = request.args.get("id", "1")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT body FROM notes WHERE id = {}".format(note_id))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "not found"


@app.route("/ping")
def ping():
    # Command injection: user-controlled host passed to a shell.
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/calc")
def calc():
    # Arbitrary code execution via eval() on user input.
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


@app.route("/import_prefs", methods=["POST"])
def import_prefs():
    # Insecure deserialization of untrusted data.
    blob = request.get_data()
    prefs = pickle.loads(blob)
    return str(prefs)


@app.route("/load_config", methods=["POST"])
def load_config():
    # Unsafe YAML load can instantiate arbitrary Python objects.
    data = request.get_data()
    cfg = yaml.load(data)
    return str(cfg)


@app.route("/fetch")
def fetch():
    # TLS verification disabled -> susceptible to MITM.
    url = request.args.get("url", "https://example.com")
    resp = requests.get(url, verify=False)
    return resp.text


def backup():
    # Writing to a predictable path in a world-writable temp dir.
    os.system("tar czf /tmp/notes-backup.tgz " + DB_PATH)


if __name__ == "__main__":
    # Debug mode on + listening on all interfaces in "production".
    app.run(host="0.0.0.0", debug=True)
