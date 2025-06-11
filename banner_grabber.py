import socket
import select
from utils import logger


def grab_banner(ip, port, timeout=2):
    """
    Récupère la bannière d'un service réseau en se connectant au port spécifié.
    
    Args:
        ip (str): Adresse IP du service cible
        port (int): Port du service cible
        timeout (int, optional): Délai d'attente en secondes. Défaut: 2
    
    Returns:
        str: Bannière du service ou chaîne vide si échec/pas de bannière
    
    Note:
        Utilise une socket non-bloquante avec select() pour éviter les blocages.
        Certains services n'envoient pas de bannière automatiquement.
    """
    try:
        # Établissement de la connexion
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Passage en mode non-bloquant pour utiliser select()
        s.setblocking(0)
        
        # Attente des données avec timeout
        ready = select.select([s], [], [], timeout)
        
        if ready[0]:
            # Des données sont disponibles
            banner = s.recv(1024).decode(errors="ignore").strip()
        else:
            # Timeout atteint, pas de bannière reçue
            banner = ""
            
        s.close()
        return banner
        
    except Exception as e:
        logger(f"[!] Banner grab failed on {ip}:{port} - {e}")
        return ""


def grab_banners(scan_results):
    """
    Récupère les bannières pour tous les ports ouverts dans les résultats de scan.
    
    Args:
        scan_results (dict): Résultats de scan au format {ip: {"ports": [port1, port2, ...]}}
    
    Returns:
        dict: Bannières au format {ip: {port: banner_string}}
    
    Note:
        Les bannières vides sont conservées dans le résultat pour maintenir
        la structure de données cohérente.
    """
    banners = {}
    
    for ip, data in scan_results.items():
        banners[ip] = {}
        
        # Récupération des bannières pour chaque port ouvert
        for port in data.get("ports", []):
            banner = grab_banner(ip, port)
            
            if banner:
                logger(f"[+] {ip}:{port} -> {banner}")
            
            # Stockage même si bannière vide pour cohérence
            banners[ip][str(port)] = banner
    
    return banners