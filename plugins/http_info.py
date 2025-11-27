import requests
from bs4 import BeautifulSoup

# Timeout razonable
TIMEOUT = 3


def run(ip, ports, scan_id, save):
    """
    Plugin: http_info
    Hace requests HTTP/HTTPS en los puertos 80/443 y guarda:
      - http_code
      - server_banner
      - title
    """

    for port in ports:
        url = None

        if port == 80:
            url = f"http://{ip}"
        elif port == 443:
            url = f"https://{ip}"
        else:
            continue

        try:
            resp = requests.get(url, timeout=TIMEOUT)

            # Guardo código HTTP
            save("http_code", str(resp.status_code), ip)

            # Banner del servidor
            if "Server" in resp.headers:
                save("server_banner", resp.headers["Server"], ip)

            # Parsear título HTML si existe
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string if soup.title else None

            if title:
                save("title", title.strip(), ip)

        except Exception as e:
            # Si no responde, no guardamos nada
            pass
