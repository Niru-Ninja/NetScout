from flask import Blueprint, jsonify
from core.database import get_conn

blueprint = Blueprint("api", __name__)

@blueprint.route("/results")
def api_results():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT ips.ip AS ip, GROUP_CONCAT(ports.port) AS ports
        FROM ips
        LEFT JOIN ports ON ips.id = ports.ip_id
        GROUP BY ips.id
    """)

    rows = cur.fetchall()
    conn.close()

    result = []
    for row in rows:
        ports = row["ports"].split(",") if row["ports"] else []
        result.append({
            "ip": row["ip"],
            "ports": ports
        })

    return jsonify(result)
