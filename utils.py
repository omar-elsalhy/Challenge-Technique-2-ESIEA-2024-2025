"""
Utilitaires pour le scanner réseau Python.

Ce module fournit des fonctions d'aide pour la validation d'IP, le parsing de ports,
le logging et la mesure de performance.
"""

import ipaddress
import logging
from functools import wraps
from time import time
from typing import List, Callable, Any


# Configuration du système de logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(message)s'
)


def logger(message: str) -> None:
    """
    Fonction de logging simplifiée pour l'application.
    
    Args:
        message (str): Message à logger
    
    Note:
        Utilise le niveau INFO par défaut. Pour un vrai projet,
        considérer différents niveaux (DEBUG, WARNING, ERROR).
    """
    logging.info(message)


def validate_ip(ip: str) -> bool:
    """
    Valide une adresse IP (IPv4 ou IPv6).
    
    Args:
        ip (str): Chaîne représentant une adresse IP
    
    Returns:
        bool: True si l'IP est valide, False sinon
    
    Examples:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("invalid_ip")
        False
        >>> validate_ip("2001:db8::1")
        True
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_ports(ports_str: str) -> List[int]:
    """
    Parse une chaîne de ports en liste d'entiers.
    
    Supporte les formats suivants :
    - Ports individuels séparés par des virgules : "22,80,443"
    - Plages de ports : "20-25,80,8000-8080"
    - Combinaisons : "22,80-85,443"
    
    Args:
        ports_str (str): Chaîne de ports à parser
    
    Returns:
        List[int]: Liste triée des ports uniques
    
    Raises:
        ValueError: Si le format est invalide ou contient des valeurs non-numériques
    
    Examples:
        >>> parse_ports("22,80,443")
        [22, 80, 443]
        >>> parse_ports("80-85")
        [80, 81, 82, 83, 84, 85]
        >>> parse_ports("22,80-82,443")
        [22, 80, 81, 82, 443]
    """
    ports = set()
    parts = ports_str.split(',')
    
    for part in parts:
        part = part.strip()  # Supprime les espaces éventuels
        
        if '-' in part:
            # Gestion des plages de ports
            try:
                start, end = part.split('-', 1)  # Limite à 1 split pour éviter les erreurs
                start, end = int(start.strip()), int(end.strip())
                
                if start > end:
                    raise ValueError(f"Plage invalide: {start}-{end} (début > fin)")
                if start < 1 or end > 65535:
                    raise ValueError(f"Ports hors limites: {start}-{end} (1-65535 autorisés)")
                
                ports.update(range(start, end + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Format de plage invalide: '{part}'")
                raise
        else:
            # Port individuel
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port hors limites: {port} (1-65535 autorisés)")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Port invalide: '{part}'")
    
    return sorted(ports)


def timer(func: Callable) -> Callable:
    """
    Décorateur pour mesurer le temps d'exécution d'une fonction.
    
    Args:
        func (Callable): Fonction à décorer
    
    Returns:
        Callable: Fonction décorée qui log son temps d'exécution
    
    Example:
        @timer
        def ma_fonction():
            time.sleep(1)
            return "résultat"
        
        # Affichera: [TIMER] ma_fonction executed in 1.00s
    """
    @wraps(func)  # Préserve les métadonnées de la fonction originale
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time()
        result = func(*args, **kwargs)
        end = time()
        
        execution_time = end - start
        logger(f"[TIMER] {func.__name__} executed in {execution_time:.2f}s")
        
        return result
    
    return wrapper