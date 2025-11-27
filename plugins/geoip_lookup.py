import requests

PLUGIN_NAME = "geoip_lookup"

def run(ip, ports, scan_id, save):
    """Obtiene país, región, ciudad, ISP y ASN de una IP pública."""

    # evitar consultas inútiles a IPs privadas
    private_blocks = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.")

    if ip.startswith(private_blocks):
        return  # No guardamos nada en base de datos

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"
        r = requests.get(url, timeout=5)
        data = r.json()

        if data.get("status") != "success":
            save("error", "lookup_failed", ip)
            return

        # Guardar todo en la base de datos
        for key in ("country", "regionName", "city", "isp", "org", "as"):
            val = data.get(key)
            if val:
                save(key, val, ip)

    except Exception as e:
        save("error", str(e), ip)
