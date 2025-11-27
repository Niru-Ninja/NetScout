from flask import Blueprint, render_template, request, redirect, url_for, Response
from core.database import get_conn, list_scans

blueprint = Blueprint("ui", __name__)

@blueprint.route("/")
def index():
    selected_scan = request.args.get("scan", type=int)

    # Obtener lista de scans
    scans = list_scans()

    if not scans:
        return render_template("index.html", scans=[], results=[], selected_scan=None)

    if selected_scan is None:
        selected_scan = scans[-1]["id"]  # último scan

    # Buscador
    q = request.args.get("q", "").strip()

    # === IPs escaneadas ===
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT ips.id AS ip_id, ips.ip AS ip
        FROM scan_ips
        JOIN ips ON scan_ips.ip_id = ips.id
        WHERE scan_ips.scan_id = ?
        ORDER BY ips.ip
    """, (selected_scan,))
    ip_rows = cur.fetchall()

    results = []
    ip_ids = [row["ip_id"] for row in ip_rows]

    if ip_ids:
        placeholders = ",".join("?" * len(ip_ids))

        # === Puertos ===
        cur.execute(f"""
            SELECT ip_id, port
            FROM ports
            WHERE scan_id = ? AND ip_id IN ({placeholders})
            ORDER BY port ASC
        """, (selected_scan, *ip_ids))
        port_rows = cur.fetchall()

        ports_by_ip = {}
        for p in port_rows:
            ports_by_ip.setdefault(p["ip_id"], []).append(p["port"])

        # === Plugins ===
        cur.execute(f"""
            SELECT ip_id, plugin, key, value
            FROM plugin_results
            WHERE scan_id = ? AND ip_id IN ({placeholders})
            ORDER BY plugin ASC, key ASC
        """, (selected_scan, *ip_ids))
        plugin_rows = cur.fetchall()

        plugins_by_ip = {}
        for pr in plugin_rows:
            plugins_by_ip.setdefault(pr["ip_id"], []).append({
                "plugin": pr["plugin"],
                "key": pr["key"],
                "value": pr["value"]
            })

        # === Empaquetar ===
        for row in ip_rows:
            ip_id = row["ip_id"]
            results.append({
                "ip": row["ip"],
                "ports": ports_by_ip.get(ip_id, []),
                "plugins": plugins_by_ip.get(ip_id, [])
            })

    conn.close()

    # --- FILTRO DE BUSQUEDA ---
    q = request.args.get("q", "").strip().lower()
    if q:
        filtered = []
        for item in results:
            text = item["ip"].lower()

            # puertos
            if item["ports"]:
                text += " " + " ".join(str(p) for p in item["ports"])

            # plugins
            if item["plugins"]:
                for p in item["plugins"]:
                    text += f" {p['plugin']} {p['key']} {p['value']}".lower()

            if q in text:
                filtered.append(item)

        results = filtered

    return render_template("index.html",
                           scans=scans,
                           selected_scan=selected_scan,
                           results=results)


@blueprint.route("/delete_scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    conn = get_conn()
    cur = conn.cursor()

    # Borrar primero los puertos asociados
    cur.execute("DELETE FROM ports WHERE scan_id = ?", (scan_id,))

    # Borrar el scan
    cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    conn.commit()
    conn.close()

    return redirect(url_for("ui.index"))


@blueprint.route("/export_ips/<int:scan_id>")
def export_ips(scan_id):
    search = request.args.get("search", "").strip()

    conn = get_conn()
    cur = conn.cursor()

    if search:
        cur.execute("""
            SELECT DISTINCT ips.ip
            FROM ips
            JOIN scan_ips ON scan_ips.ip_id = ips.id
            LEFT JOIN ports ON ports.ip_id = ips.id AND ports.scan_id = scan_ips.scan_id
            LEFT JOIN plugin_results ON plugin_results.ip_id = ips.id AND plugin_results.scan_id = scan_ips.scan_id
            WHERE scan_ips.scan_id = ?
              AND (
                    ips.ip LIKE ?
                 OR CAST(ports.port AS TEXT) LIKE ?
                 OR plugin_results.value LIKE ?
              )
            ORDER BY ips.ip;
        """, (scan_id, f"%{search}%", f"%{search}%", f"%{search}%"))
    else:
        cur.execute("""
            SELECT DISTINCT ips.ip
            FROM ips
            JOIN scan_ips ON scan_ips.ip_id = ips.id
            WHERE scan_ips.scan_id = ?
            ORDER BY ips.ip;
        """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    content = "\n".join([r["ip"] for r in rows])

    return Response(
        content,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id}_ips.txt"
        }
    )
