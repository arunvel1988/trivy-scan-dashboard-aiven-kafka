from kafka import KafkaConsumer
import json
import sqlite3
from datetime import datetime

# -----------------------------
# Database Setup
# -----------------------------
conn = sqlite3.connect("security.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    timestamp TEXT,
    image TEXT,
    severity TEXT,
    vuln_id TEXT,
    package TEXT,
    fixed_version TEXT,
    title TEXT
)
""")
conn.commit()

# -----------------------------
# Kafka Consumer (Aiven SSL)
# -----------------------------
consumer = KafkaConsumer(
    "trivy-security",
    bootstrap_servers="arunvel1988-kafka-arunvel1988.e.aivencloud.com:14253",
    security_protocol="SSL",
    ssl_cafile="certs/ca.pem",
    ssl_certfile="certs/service.cert",
    ssl_keyfile="certs/service.key",
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    auto_offset_reset="latest",
    enable_auto_commit=True
)

print("Kafka consumer started...")

# -----------------------------
# Consume Forever
# -----------------------------
for msg in consumer:
    report = msg.value
    ts = datetime.utcnow().isoformat()  # timestamp when consumed

    for result in report.get("Results", []):
        image = result.get("Target", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            cur.execute("""
                INSERT INTO vulnerabilities
                (timestamp, image, severity, vuln_id, package, fixed_version, title)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ts,
                image,
                vuln.get("Severity"),
                vuln.get("VulnerabilityID"),
                vuln.get("PkgName"),
                vuln.get("FixedVersion"),
                vuln.get("Title")
            ))

    conn.commit()
