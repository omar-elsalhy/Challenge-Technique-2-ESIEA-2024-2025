"""
Utilitaires pour le scanner réseau Python.

Ce module fournit des fonctions d'aide pour la validation d'IP, le parsing de ports,
le logging avec support GUI et la mesure de performance.
"""

import ipaddress
import logging
from functools import wraps
from time import time
from typing import List, Callable, Any, Optional, Protocol


# Variable globale pour stocker la référence du widget GUI de sortie
_gui_output_widget: Optional['GUIOutputWidget'] = None


class GUIOutputWidget(Protocol):
    """
    Protocole définissant l'interface requise pour un widget de sortie GUI.
    
    Cette interface permet de découpler le code du framework GUI spécifique
    utilisé (tkinter, PyQt, etc.).
    """
    
    def insert(self, position: str, text: str) -> None:
        """
        Insère du texte à la position spécifiée.
        
        Args:
            position: Position d'insertion (ex: "end" pour la fin)
            text: Texte à insérer
        """
        ...
    
    def see(self, position: str) -> None:
        """
        Fait défiler le widget pour rendre visible la position spécifiée.
        
        Args:
            position: Position à rendre visible (ex: "end" pour la fin)
        """
        ...


# Configuration du système de logging pour la console
logging.basicConfig(
    level=logging.INFO, 
    format='%(message)s'
)


def set_output_widget(widget: Optional[GUIOutputWidget]) -> None:
    """
    Configure le widget GUI pour la sortie des logs.
    
    Cette fonction permet d'associer un widget GUI (comme un Text widget tkinter)
    au système de logging pour afficher les messages à la fois en console et dans l'interface.
    
    Args:
        widget: Widget GUI supportant les méthodes insert() et see(), ou None pour désactiver
        
    Example:
        # Avec tkinter
        import tkinter as tk
        root = tk.Tk()
        text_widget = tk.Text(root)
        set_output_widget(text_widget)
        
        # Pour désactiver le logging GUI
        set_output_widget(None)
    """
    global _gui_output_widget
    _gui_output_widget = widget


def logger(message: str) -> None:
    """
    Fonction de logging hybride pour l'application.
    
    Affiche les messages à la fois dans la console et dans le widget GUI
    s'il a été configuré via set_output_widget().
    
    Args:
        message: Message à logger
        
    Note:
        - Les messages sont toujours affichés en console
        - L'affichage GUI est conditionnel selon la configuration
        - Le widget GUI défile automatiquement vers le dernier message
        
    Example:
        logger("[INFO] Application démarrée")
        logger("[ERROR] Connexion échouée")
    """
    # Affichage console
    if _gui_output_widget is None:
        print(message)

    
    # Affichage GUI (conditionnel)
    if _gui_output_widget is not None:
        try:
            _gui_output_widget.insert("end", message + "\n")
            _gui_output_widget.see("end")
        except Exception as e:
            # En cas d'erreur avec le widget GUI, on continue avec la console uniquement
            print(f"[WARNING] Erreur widget GUI: {e}")


def validate_ip(ip: str) -> bool:
    """
    Valide une adresse IP (IPv4 ou IPv6).
    
    Args:
        ip: Chaîne représentant une adresse IP
    
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
        ports_str: Chaîne de ports à parser
    
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
        func: Fonction à décorer
    
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
