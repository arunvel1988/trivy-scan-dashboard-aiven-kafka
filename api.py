from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("security.db")

# -----------------------------
# Latest Run Summary
# -----------------------------
@app.route("/summary")
def summary():
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT MAX(timestamp) FROM vulnerabilities")
    latest_ts = cur.fetchone()[0]

    cur.execute("""
        SELECT severity, COUNT(*)
        FROM vulnerabilities
        WHERE timestamp = ?
        GROUP BY severity
    """, (latest_ts,))

    return jsonify({row[0]: row[1] for row in cur.fetchall()})

# -----------------------------
# Latest Run Vulnerabilities
# -----------------------------
@app.route("/latest")
def latest():
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT MAX(timestamp) FROM vulnerabilities")
    latest_ts = cur.fetchone()[0]

    cur.execute("""
        SELECT timestamp, image, severity, vuln_id, package, fixed_version, title
        FROM vulnerabilities
        WHERE timestamp = ?
        ORDER BY image ASC
        LIMIT 1000
    """, (latest_ts,))

    rows = cur.fetchall()
    return jsonify(rows)

# -----------------------------
# Historical Trend (Optional)
# -----------------------------
@app.route("/history")
def history():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT timestamp, severity, COUNT(*)
        FROM vulnerabilities
        GROUP BY timestamp, severity
        ORDER BY timestamp ASC
    """)
    return jsonify(cur.fetchall())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
