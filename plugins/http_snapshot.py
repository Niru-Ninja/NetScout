import requests

MAX_SAVE_LEN = 5000   # límite razonable para no llenar la DB
TIMEOUT = 4

def run(ip, ports, scan_id, save):
    print(f"[plugin http_snapshot] {ip}:{ports}")

    for port in ports:
        if port not in (80, 443):
            continue

        url = f"http://{ip}" if port == 80 else f"https://{ip}"

        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False)
        except Exception as e:
            print(f"[snapshot] error {url}: {e}")
            continue

        text = resp.text[:MAX_SAVE_LEN]

        save("snapshot_status", str(resp.status_code), ip)
        save("snapshot_server", resp.headers.get("Server", "—"), ip)
        save("snapshot_length", str(len(resp.text)), ip)
        save("snapshot_html", text, ip)   # se guarda truncado

        print(f"[snapshot] saved initial HTML of {ip} ({len(text)} chars)")
