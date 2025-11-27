import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class RateLimiter:
    def __init__(self, rate_per_sec):
        self.rate = rate_per_sec
        self.allowance = rate_per_sec
        self.last_check = time.time()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            time_passed = now - self.last_check
            self.last_check = now
            self.allowance += time_passed * self.rate

            if self.allowance > self.rate:
                self.allowance = self.rate

            if self.allowance < 1.0:
                time.sleep((1.0 - self.allowance) / self.rate)
                self.allowance = 0
            else:
                self.allowance -= 1.0


def scan_port(ip, port, timeout, rate_limiter=None):
    """Devuelve True si el puerto está abierto."""
    if rate_limiter:
        rate_limiter.wait()

    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False


def scan_ip(ip, ports, timeout, on_port_open=None, rate_limiter=None):
    """Escanea todos los puertos de una IP."""
    open_ports = []

    for port in ports:
        if scan_port(ip, port, timeout, rate_limiter):
            open_ports.append(port)
            if on_port_open:
                on_port_open(ip, port)

    return open_ports


def scan_network(
    ips,
    ports,
    max_workers=50,
    rate_sec = 200,
    timeout=1.0,
    on_ip_start=None,
    on_port_open=None,
    on_ip_end=None
):
    """
    Escanea múltiples IPs en paralelo con callbacks.
    """
    results = {}
    futures = []
    rate_limiter = RateLimiter(rate_per_sec=rate_sec)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip in ips:

            # Callback cuando empieza
            if on_ip_start:
                on_ip_start(ip)

            fut = executor.submit(
                scan_ip,
                ip,
                ports,
                timeout,
                on_port_open,
                rate_limiter
            )
            futures.append((ip, fut))

        for ip, fut in futures:
            open_ports = fut.result()
            results[ip] = open_ports

            # Callback cuando termina
            if on_ip_end:
                on_ip_end(ip, open_ports)

    return results
