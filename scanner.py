# scanner.py : Pour le scan d'IP et de ports

import socket
import ipaddress

def is_host_up(ip, ports=[80, 443], timeout=0.5):
    #Vérifie si une machine est active via TCP connect().
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except:
            continue
    return False

def scan_port(ip, port, timeout=1):
     #Scanne un port TCP via connect().
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return True
    except socket.timeout:
        pass
    except socket.error as e:
        print(f"[!] Erreur socket : {e}")
    return False

def scan_targets(targets, ports, timeout=1):
    #Scanne une liste d'IP pour détecter les ports ouverts.
    
    results = {}

    for target in targets:
        try:
            ip_obj = ipaddress.ip_address(target)
        except ValueError:
            print(f"[!] Adresse IP invalide : {target}")
            continue

        if is_host_up(target, ports):
            open_ports = []
            for port in ports:
                if scan_port(target, port, timeout):
                    open_ports.append(port)
            results[target] = {
                "open_ports": open_ports
            }
        else:
            print(f"[-] {target} est injoignable.")

    return results
