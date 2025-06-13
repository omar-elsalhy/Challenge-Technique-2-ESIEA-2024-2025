# ==============================================================================
# SCANNER.PY - MODULE DE SCAN RÉSEAU
# ==============================================================================
# Ce module implémente un scanner réseau inspiré de Nmap, capable de :
# - Détecter les hôtes actifs sur le réseau (ping)
# - Scanner les ports TCP et UDP
# - Gérer différents formats d'adresses IP (simple, CIDR, plages)
# - Utiliser le multi-threading pour améliorer les performances
# ==============================================================================

# Importation des bibliothèques nécessaires
import socket          # Pour les connexions réseau TCP/UDP
import ipaddress       # Pour la manipulation des adresses IP et réseaux
import subprocess      # Pour exécuter des commandes système (ping)
import platform        # Pour détecter le système d'exploitation
from utils import logger, validate_ip, timer  # Fonctions utilitaires personnalisées
from time import sleep  # Pour ajouter des délais entre les scans
from banner_grabber import grab_banner  # Module pour récupérer les bannières
from concurrent.futures import ThreadPoolExecutor, as_completed  # Multi-threading


def is_host_alive(ip, timeout=1):
    """
    FONCTION DE DÉTECTION D'HÔTES ACTIFS
    ===================================
    Utilise la commande ping du système pour vérifier si un hôte répond.
    Cette méthode est plus fiable que les autres techniques car elle utilise
    les outils système natifs.
    
    Paramètres:
        ip (str): Adresse IP à tester (ex: "192.168.1.1")
        timeout (int): Temps d'attente en secondes avant abandon
    
    Retourne:
        bool: True si l'hôte répond, False sinon
    
    Principe:
        1. Détecte le système d'exploitation (Windows ou Linux/Mac)
        2. Adapte la commande ping selon l'OS
        3. Exécute la commande et analyse le code de retour
    """
    
    # Adaptation de la commande ping selon l'OS
    # Windows utilise -n pour le nombre de paquets, Unix utilise -c
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Construction de la commande ping complète
    # ping -c 1 -w timeout_ms ip (Linux) ou ping -n 1 -w timeout_ms ip (Windows)
    command = ['ping', param, '1', '-w', str(timeout * 1000), ip]

    try:
        # Exécution de la commande ping
        # stdout/stderr=DEVNULL masque la sortie pour éviter l'encombrement
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Code de retour 0 = succès (hôte répond), autre = échec
        return result.returncode == 0
        
    except Exception as e:
        # Gestion des erreurs (commande inexistante, permissions, etc.)
        logger(f"[!] Ping error on {ip}: {e}")
        return False


def parse_ip_range(target):
    """
    ANALYSEUR DE FORMATS D'ADRESSES IP
    ==================================
    Convertit différents formats d'entrée en liste d'adresses IP individuelles.
    Supporte 3 formats principaux utilisés dans les outils de sécurité réseau.
    
    Paramètres:
        target (str): Format d'entrée à analyser
        
    Formats supportés:
        - IP simple: "192.168.1.1" → ["192.168.1.1"]
        - CIDR: "192.168.1.0/24" → ["192.168.1.0", "192.168.1.1", ..., "192.168.1.255"]
        - Plage: "192.168.1.1-192.168.1.10" → ["192.168.1.1", "192.168.1.2", ..., "192.168.1.10"]
    
    Retourne:
        list: Liste des adresses IP à scanner
    """
    
    # Nettoyage de l'entrée (suppression des espaces)
    target = target.strip()
    
    # ==========================================
    # FORMAT PLAGE : IP1-IP2
    # ==========================================
    if '-' in target:
        try:
            # Séparation des IP de début et de fin
            start_ip, end_ip = target.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Validation des adresses IP avec la fonction utilitaire
            if not validate_ip(start_ip) or not validate_ip(end_ip):
                logger(f"[!] Invalid IP range format: {target}")
                return []
            
            # Conversion en objets IPv4Address pour manipulation mathématique
            start_addr = ipaddress.IPv4Address(start_ip)
            end_addr = ipaddress.IPv4Address(end_ip)
            
            # Vérification que l'IP de début est inférieure à celle de fin
            if start_addr > end_addr:
                logger(f"[!] Invalid range: start IP {start_ip} is greater than end IP {end_ip}")
                return []
            
            # Génération de toutes les IPs dans la plage
            ips = []
            current = start_addr
            while current <= end_addr:
                ips.append(str(current))  # Conversion en string pour utilisation
                current += 1  # Incrémentation de l'adresse IP
            
            logger(f"[*] Parsed IP range {target}: {len(ips)} addresses")
            return ips
            
        except Exception as e:
            logger(f"[!] Error parsing IP range {target}: {e}")
            return []
    
    # ==========================================
    # FORMAT CIDR : 192.168.1.0/24
    # ==========================================
    elif '/' in target:
        try:
            # Utilisation de la bibliothèque ipaddress pour parser le CIDR
            # strict=False permet d'accepter des adresses comme 192.168.1.1/24
            return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        except Exception as e:
            logger(f"[!] Error parsing CIDR {target}: {e}")
            return []
    
    # ==========================================
    # IP SIMPLE : 192.168.1.1
    # ==========================================
    else:
        if validate_ip(target):
            return [target]  # Retourne une liste avec une seule IP
        else:
            logger(f"[!] Invalid IP format: {target}")
            return []


@timer  # Décorateur pour mesurer le temps d'exécution de la fonction
def scan_targets(targets, ports, udp=False, delay=None, timeout=2, threads=10, exclude=None, verbose=False):
    """
    FONCTION PRINCIPALE DE SCAN
    ===========================
    Orchestre l'ensemble du processus de scan : parsing des cibles, détection d'hôtes,
    scan de ports et agrégation des résultats. Utilise le multi-threading pour
    améliorer les performances.
    
    Paramètres:
        targets (list): Liste des cibles à scanner (formats variés)
        ports (list): Liste des ports à tester
        udp (bool): True pour scan UDP, False pour TCP
        delay (float): Délai entre chaque scan de port (en secondes)
        timeout (int): Timeout pour les connexions réseau
        threads (int): Nombre de threads parallèles
        exclude (list): Liste d'IPs à exclure du scan
        verbose (bool): Mode verbeux pour plus de logs
        
    Retourne:
        dict: Dictionnaire des résultats par IP
    """
    
    # Initialisation des structures de données
    results = {}  # Stockage des résultats finaux
    exclude = set(exclude or [])  # Conversion en set pour recherche O(1)

    def scan_ip(ip):
        """
        FONCTION INTERNE DE SCAN D'UNE IP
        =================================
        Cette fonction est exécutée par chaque thread pour scanner une IP.
        Elle encapsule toute la logique de scan pour une adresse.
        """
        
        # ==========================================
        # PHASE 1 : VÉRIFICATIONS PRÉLIMINAIRES
        # ==========================================
        
        # Vérification si l'IP est dans la liste d'exclusion
        if ip in exclude:
            logger(f"[~] Skipping excluded IP: {ip}")
            return None  # Retour None = pas de résultat à traiter

        # Validation du format de l'IP
        if not validate_ip(ip):
            logger(f"[!] Invalid IP: {ip}")
            return None

        # Log en mode verbeux
        if verbose:
            logger(f"[*] Probing host {ip}...")

        # ==========================================
        # PHASE 2 : DÉTECTION D'HÔTE ACTIF
        # ==========================================
        
        # Test de connectivité avec ping
        if not is_host_alive(ip, timeout=timeout):
            logger(f"[-] Host {ip} is down.")
            return None  # Pas la peine de scanner les ports si l'hôte ne répond pas
        else:
            logger(f"[+] Host {ip} is active.")

        # ==========================================
        # PHASE 3 : SCAN DES PORTS
        # ==========================================
        
        open_ports = []  # Liste des ports trouvés ouverts
        for port in ports:
            # Choix de la méthode de scan selon le protocole
            if udp:
                if udp_scan(ip, port, timeout=timeout):
                    open_ports.append(port)
            else:
                if tcp_connect_scan(ip, port, timeout=timeout):
                    open_ports.append(port)
            
            # Délai optionnel entre les scans (pour éviter la détection IDS)
            if delay:
                sleep(delay)

        # ==========================================
        # PHASE 4 : IDENTIFICATION DES SERVICES
        # ==========================================
        
        # Mapping port → nom de service (ex: 80 → "http")
        service_map = {}
        for port in open_ports:
            try:
                # getservbyport() traduit numéro de port en nom de service
                service_name = socket.getservbyport(port, 'tcp') if not udp else 'udp'
                service_map[str(port)] = service_name
            except:
                # Si le service n'est pas dans /etc/services
                service_map[str(port)] = 'unknown'

        # Retour des résultats pour cette IP
        return ip, {
            "ports": open_ports,      # Liste des ports ouverts
            "services": service_map,  # Mapping port → service
            "banners": {}            # Placeholder pour les bannières
        }

    # ==========================================
    # PARSING DE TOUTES LES CIBLES
    # ==========================================
    
    all_ips = []  # Liste finale de toutes les IPs à scanner
    for target in targets:
        try:
            # Conversion de chaque cible en liste d'IPs
            ips = parse_ip_range(target)
            if not ips:
                logger(f"[!] No valid IPs found for target: {target}")
                continue
            all_ips.extend(ips)  # Ajout à la liste globale
        except Exception as e:
            logger(f"[!] Error parsing target {target}: {e}")

    # ==========================================
    # EXÉCUTION MULTI-THREADÉE
    # ==========================================
    
    # Création d'un pool de threads
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Soumission de toutes les tâches aux threads
        # future_to_ip permet de mapper chaque future à son IP
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in all_ips}
        
        # Récupération des résultats au fur et à mesure
        for future in as_completed(future_to_ip):
            result = future.result()  # Récupération du résultat du thread
            if result:  # Si le scan a trouvé quelque chose
                ip, data = result
                results[ip] = data  # Stockage dans les résultats finaux

    return results


def tcp_connect_scan(ip, port, timeout=1):
    """
    SCANNER TCP CONNECT
    ===================
    Implémente la méthode de scan TCP "connect", qui établit une connexion
    complète TCP (3-way handshake). Cette méthode est fiable mais détectable.
    
    Paramètres:
        ip (str): Adresse IP cible
        port (int): Port à tester
        timeout (int): Timeout de connexion
        
    Retourne:
        bool: True si le port est ouvert, False sinon
        
    Principe:
        1. Création d'un socket TCP
        2. Tentative de connexion sur IP:port
        3. Analyse du code de retour
    """
    try:
        # Création d'un socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Configuration du timeout pour éviter les blocages
            s.settimeout(timeout)
            
            # Tentative de connexion
            # connect_ex() retourne 0 si succès, code d'erreur sinon
            result = s.connect_ex((ip, port))
            
            if result == 0:  # Connexion réussie = port ouvert
                logger(f"[+] TCP Open: {ip}:{port}")
                return True
                # Le socket se ferme automatiquement grâce au 'with'
                
    except Exception as e:
        # Gestion des erreurs réseau, permissions, etc.
        logger(f"[!] TCP scan error on {ip}:{port} - {e}")
    
    return False  # Par défaut, considère le port comme fermé


def udp_scan(ip, port, timeout=2):
    """
    SCANNER UDP
    ===========
    Implémente le scan UDP, plus complexe que TCP car UDP est un protocole
    sans connexion. La détection repose sur l'absence de réponse ICMP.
    
    Paramètres:
        ip (str): Adresse IP cible
        port (int): Port UDP à tester
        timeout (int): Timeout d'attente de réponse
        
    Retourne:
        bool: True si le port semble ouvert, False sinon
        
    Principe UDP:
        - Si le port est ouvert : pas de réponse ou réponse du service
        - Si le port est fermé : message ICMP "Port Unreachable"
        - Problème : beaucoup de firewalls bloquent l'ICMP
    """
    try:
        # Création d'un socket UDP (SOCK_DGRAM = UDP)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            
            # Envoi d'un paquet UDP vide vers le port cible
            # \x00 = byte null, payload minimal
            s.sendto(b'\x00', (ip, port))
            
            try:
                # Tentative de réception d'une réponse
                data, _ = s.recvfrom(1024)  # Buffer de 1024 bytes
                logger(f"[+] UDP Open (response): {ip}:{port}")
                return True  # Réponse reçue = service actif
                
            except socket.timeout:
                # Pas de réponse dans le délai imparti
                # En UDP, c'est souvent signe que le port est ouvert
                # mais que le service ne répond pas à notre payload
                logger(f"[?] UDP No response (could be open): {ip}:{port}")
                return True  # Considéré comme potentiellement ouvert
                
    except Exception as e:
        # Erreurs diverses (réseau, permissions, ICMP Port Unreachable, etc.)
        logger(f"[!] UDP scan error on {ip}:{port} - {e}")
    
    return False  # En cas d'erreur, considère le port comme fermé

# ==============================================================================
# RÉSUMÉ DU FONCTIONNEMENT GLOBAL
# ==============================================================================
#
# 1. PARSING : Conversion des formats d'entrée en listes d'IPs
# 2. DISTRIBUTION : Répartition des IPs sur plusieurs threads
# 3. DÉTECTION : Test ping pour identifier les hôtes actifs
# 4. SCAN : Test de connectivité sur chaque port
# 5. AGRÉGATION : Compilation des résultats dans une structure unifiée
#
# Ce module suit les principes des scanners réseau modernes :
# - Fiabilité : gestion d'erreurs complète
# - Performance : multi-threading
# - Flexibilité : support de multiples formats d'entrée
# - Compatibilité : fonctionnement multi-plateforme
# ==============================================================================