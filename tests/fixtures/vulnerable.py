import os
import subprocess
import hashlib
import sqlite3

# SQL injection via string formatting
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cursor.fetchone()

# Command injection via shell=True
def run_report(report_name):
    subprocess.run(f"generate_report.sh {report_name}", shell=True)

# Weak hash
def cache_key(data):
    return hashlib.md5(data.encode()).hexdigest()

# Hardcoded secret
api_key = "sk-abc123def456ghi789"
