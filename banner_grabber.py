import socket
import select
from utils import logger

def grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.setblocking(0)

        ready = select.select([s], [], [], timeout)
        if ready[0]:
            banner = s.recv(1024).decode(errors="ignore").strip()
        else:
            banner = ""
        s.close()
        return banner
    except Exception as e:
        logger(f"[!] Banner grab failed on {ip}:{port} - {e}")
        return ""

def grab_banners(scan_results):
    banners = {}
    for ip, data in scan_results.items():
        banners[ip] = {}
        for port in data.get("ports", []):
            banner = grab_banner(ip, port)
            if banner:
                logger(f"[+] {ip}:{port} -> {banner}")
            banners[ip][port] = banner
    return banners
