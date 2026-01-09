from kafka import KafkaConsumer
import json
import sqlite3

# -----------------------------
# Database Setup
# -----------------------------
conn = sqlite3.connect("security.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    pipeline_id TEXT,
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
    pipeline_id = report.get("pipeline_id", "unknown")
    ts = report.get("timestamp")  # use timestamp from JSON

    for result in report.get("vulnerabilities", []):
        image = result.get("Target", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            cur.execute("""
                INSERT INTO vulnerabilities
                (pipeline_id, timestamp, image, severity, vuln_id, package, fixed_version, title)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pipeline_id,
                ts,
                image,
                vuln.get("Severity"),
                vuln.get("VulnerabilityID"),
                vuln.get("PkgName"),
                vuln.get("FixedVersion"),
                vuln.get("Title")
            ))

    conn.commit()
