import requests
requests.packages.urllib3.disable_warnings()

def run(ip, open_ports, scan_id, save):
    """
    Detecta qué tipo de dispositivo puede estar detrás de una IP mediante heurísticas simples.
    """
    UA = {
        "User-Agent": "Mozilla/5.0 (NetScout Scanner)"
    }

    signatures = {
        # Routers y modems
        "tplink": {
            "score": 3,
            "patterns": ["TP-Link", "tplink", "tplinklogin.net", "Archer", "tp-link", "/webpages/login.html", "userRpm"],
        },
        "sagemcom": {
            "score": 2,
            "patterns": ["Sagemcom", "sagemcom", "fast3865", "F@ST"],
        },
        "mikrotik": {
            "score": 3,
            "patterns": ["MikroTik", "RouterOS", "WebFig"],
        },
        "unifi": {
            "score": 2,
            "patterns": ["UniFi", "Ubiquiti", "UBNT"],
        },

        # CÁMARAS
        "hikvision": {
            "score": 4,
            "patterns": [
                "Hikvision", "WEB3.0 | HIKVISION", "doc/page/login.asp",
                "doc/page/main.asp", "ISAPI", "HIKVISION DIGITAL TECHNOLOGY"
            ],
        },
        "dahua": {
            "score": 4,
            "patterns": ["Dahua", "DHIP", "DVRDVS-Webs", "Dahua Technology"],
        },

        # FIREWALLS / Security appliances
        "fortinet": {
            "score": 5,
            "patterns": ["Fortinet", "FortiGate", "FGT", "FortiOS"],
        }
    }

    # Para evitar duplicados
    already_reported = set()

    for port in open_ports:
        for proto in ["http", "https"]:
            url = f"{proto}://{ip}:{port}"
            print(f"[plugin admin_panel] checking {url}")

            try:
                resp = requests.get(url, timeout=4, verify=False, headers=UA)
            except Exception:
                continue

            if resp.status_code not in [200, 301, 302, 401]:
                continue

            body = resp.text.lower()
            headers = "\n".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()

            # Buscar coincidencias
            for vendor, data in signatures.items():
                found = False
                for pattern in data["patterns"]:
                    p = pattern.lower()

                    if p in body or p in headers:
                        found = True
                        break

                if found:
                    key = f"{vendor}_detected"

                    # Evitar duplicados
                    if key in already_reported:
                        continue

                    score = data["score"]
                    save(vendor, f"score={score}", ip)
                    already_reported.add(key)

                    print(f"[plugin admin_panel] DETECTED {vendor.upper()} on {ip} (score={score})")

            # Si no coincidió con nada, guardar snapshot mínimo
            if not already_reported:
                save("admin_panel_unknown", resp.text[:200], ip)
                print(f"[plugin admin_panel] unknown on {ip}")

    return