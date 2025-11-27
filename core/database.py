# core/database.py

import sqlite3
from pathlib import Path

DB_PATH = Path("netscout.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Tablas
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_id INTEGER,
            port INTEGER,
            scan_id INTEGER,
            UNIQUE(ip_id, port),
            FOREIGN KEY(ip_id) REFERENCES ips(id),
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS plugin_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_id INTEGER,
            plugin TEXT,
            key TEXT,
            value TEXT,
            scan_id INTEGER,
            FOREIGN KEY(ip_id) REFERENCES ips(id),
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip_id INTEGER,
            UNIQUE(scan_id, ip_id),
            FOREIGN KEY(scan_id) REFERENCES scans(id),
            FOREIGN KEY(ip_id) REFERENCES ips(id)
            )
    """)

    # Mejor rendimiento para escrituras concurrentes
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")

    conn.commit()
    conn.close()


# =========================
#   CRUD BASICO
# =========================

def add_ip(ip: str) -> int:
    """Inserta una IP si no existe, y devuelve su id."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("INSERT OR IGNORE INTO ips (ip) VALUES (?)", (ip,))
    conn.commit()

    # Obtener ID incluso si ya existía
    cur.execute("SELECT id FROM ips WHERE ip = ?", (ip,))
    row = cur.fetchone()

    conn.close()
    return row["id"]


def add_port(ip_id: int, port: int, scan_id: int):
    """Guarda un puerto abierto para una IP."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT OR IGNORE INTO ports (ip_id, port, scan_id)
        VALUES (?, ?, ?)
    """, (ip_id, port, scan_id))

    conn.commit()
    conn.close()


def add_plugin_result(ip_id: int, plugin: str, key: str, value: str, scan_id: int):
    """Guarda datos provenientes de un plugin."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO plugin_results (ip_id, plugin, key, value, scan_id)
        VALUES (?, ?, ?, ?, ?)
    """, (ip_id, plugin, key, value, scan_id))

    conn.commit()
    conn.close()


def get_results():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT ips.ip AS ip, ports.port AS port
        FROM ips
        LEFT JOIN ports ON ips.id = ports.ip_id
        ORDER BY ips.ip ASC, ports.port ASC
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def list_scans():
    # Devuelve todos los scans registrados.
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp
        FROM scans
        ORDER BY id ASC
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def create_scan():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("INSERT INTO scans DEFAULT VALUES")
    scan_id = cur.lastrowid

    conn.commit()
    conn.close()
    return scan_id


def save_scan_ip(scan_id, ip_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO scan_ips (scan_id, ip_id)
        VALUES (?, ?)
    """, (scan_id, ip_id))
    conn.commit()
    conn.close()