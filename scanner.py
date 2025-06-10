import socket
import ipaddress
from utils import logger, validate_ip, timer
from time import sleep

@timer
def scan_targets(targets, ports, udp=False, delay=None):
    # Scanne une liste d'IP sur les ports spécifiés en TCP ou UDP
    results = {}

    for target in targets:
        try:
            ips = []
            if '/' in target:
                ips = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
            else:
                ips = [target]

            for ip in ips:
                if not validate_ip(ip):
                    logger(f"[!] Invalid IP: {ip}")
                    continue

                logger(f"[*] Scanning {ip}...")
                open_ports = []
                for port in ports:
                    if udp:
                        if udp_scan(ip, port):
                            open_ports.append(port)
                    else:
                        if tcp_connect_scan(ip, port):
                            open_ports.append(port)
                    if delay:
                        sleep(delay)

                if open_ports:
                    results[ip] = {"ports": open_ports}

        except Exception as e:
            logger(f"[!] Error scanning {target}: {e}")

    return results

def tcp_connect_scan(ip, port, timeout=1):
    # Essaie de se connecter à un port TCP pour vérifier s’il est ouvert
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                logger(f"[+] TCP Open: {ip}:{port}")
                return True
    except Exception as e:
        logger(f"[!] TCP scan error on {ip}:{port} - {e}")
    return False

def udp_scan(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'\x00', (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                logger(f"[+] UDP Open (response): {ip}:{port}")
                return True
            except socket.timeout:
                logger(f"[?] UDP No response (could be open): {ip}:{port}")
                return True
    except Exception as e:
        logger(f"[!] UDP scan error on {ip}:{port} - {e}")
    return False