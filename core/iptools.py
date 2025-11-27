import ipaddress

# --- validar una IP ---
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# --- validar rango: "A-B" ---
def parse_range(r: str) -> list[str]:
    """
    Convierte "192.168.0.0-192.168.0.10" a
    ["192.168.0.0", ..., "192.168.0.10"]
    """
    if "-" not in r:
        raise ValueError("El rango debe contener '-'")

    a, b = r.split("-")
    try:
        start = ipaddress.ip_address(a)
        end = ipaddress.ip_address(b)
    except:
        raise ValueError("IP inválida en el rango")

    if int(end) < int(start):
        raise ValueError("El rango tiene fin menor que el inicio")

    return [str(ip) for ip in ipaddress.summarize_address_range(start, end)][0].hosts()


def expand_range(r: str) -> list[str]:
    """Expande rango sin comprimir, IP por IP."""
    if "-" not in r:
        raise ValueError("Rango inválido, falta '-'")

    a, b = r.split("-")
    start = ipaddress.ip_address(a)
    end = ipaddress.ip_address(b)

    if int(end) < int(start):
        raise ValueError("El rango tiene fin menor que el inicio")

    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end)+1)]
