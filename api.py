from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("security.db")

@app.route("/summary")
def summary():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT severity, COUNT(*)
        FROM vulnerabilities
        GROUP BY severity
    """)

    return jsonify({row[0]: row[1] for row in cur.fetchall()})

@app.route("/latest")
def latest():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT timestamp, image, severity, vuln_id, package, fixed_version, title
        FROM vulnerabilities
        ORDER BY timestamp DESC
        LIMIT 1000
    """)

    rows = cur.fetchall()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
