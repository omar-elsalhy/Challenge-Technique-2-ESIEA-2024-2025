import socket
import ipaddress
import subprocess
import platform
from utils import logger, validate_ip, timer
from time import sleep
from banner_grabber import grab_banner


def is_host_alive(ip, timeout=1):
    """
    Ping l'hôte pour voir s'il est actif.
    Compatible Windows/Linux.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(timeout * 1000), ip]

    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        logger(f"[!] Ping error on {ip}: {e}")
        return False


def parse_ip_range(target):
    """
    Parse différents formats d'IP :
    - IP simple : 127.0.0.1
    - CIDR : 192.168.1.0/24
    - Plage : 127.0.0.1-127.0.0.5
    
    Retourne une liste d'IPs.
    """
    target = target.strip()
    
    # Format plage : IP1-IP2
    if '-' in target:
        try:
            start_ip, end_ip = target.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Validation des IPs
            if not validate_ip(start_ip) or not validate_ip(end_ip):
                logger(f"[!] Invalid IP range format: {target}")
                return []
            
            start_addr = ipaddress.IPv4Address(start_ip)
            end_addr = ipaddress.IPv4Address(end_ip)
            
            if start_addr > end_addr:
                logger(f"[!] Invalid range: start IP {start_ip} is greater than end IP {end_ip}")
                return []
            
            # Génération de la liste des IPs dans la plage
            ips = []
            current = start_addr
            while current <= end_addr:
                ips.append(str(current))
                current += 1
            
            logger(f"[*] Parsed IP range {target}: {len(ips)} addresses")
            return ips
            
        except Exception as e:
            logger(f"[!] Error parsing IP range {target}: {e}")
            return []
    
    # Format CIDR : 192.168.1.0/24
    elif '/' in target:
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        except Exception as e:
            logger(f"[!] Error parsing CIDR {target}: {e}")
            return []
    
    # IP simple
    else:
        if validate_ip(target):
            return [target]
        else:
            logger(f"[!] Invalid IP format: {target}")
            return []


@timer
def scan_targets(targets, ports, udp=False, delay=None):
    results = {}

    for target in targets:
        try:
            # Utilisation de la nouvelle fonction de parsing
            ips = parse_ip_range(target)
            
            if not ips:
                logger(f"[!] No valid IPs found for target: {target}")
                continue

            for ip in ips:
                # Vérification si hôte est alive ou non
                logger(f"[*] Probing host {ip}...")
                if not is_host_alive(ip):
                    logger(f"[-] Host {ip} is down or not responding.")
                    continue
                else:
                    logger(f"[+] Host {ip} is active.")

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

                service_map = {str(port): socket.getservbyport(port, 'tcp') if not udp else 'udp' for port in open_ports}
                #banner_map = {str(port): grab_banner(ip, port) for port in open_ports}
                results[ip] = {
                    "ports": open_ports,
                    "services": service_map,
                    "banners": {}
                }

        except Exception as e:
            logger(f"[!] Error scanning {target}: {e}")

    return results


def tcp_connect_scan(ip, port, timeout=1):
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