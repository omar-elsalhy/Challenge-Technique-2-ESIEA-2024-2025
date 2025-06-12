"""
Module de capture de paquets réseau utilisant Scapy.

Ce module fournit des fonctionnalités pour capturer et analyser les paquets réseau.
"""

from typing import Optional, Callable
from scapy.all import sniff, wrpcap, Packet
from utils import logger


def packet_callback(packet: Packet) -> None:
    """
    Traite les paquets capturés et affiche leur résumé dans les logs.
    
    Args:
        packet: Le paquet réseau capturé
    """
    summary = packet.summary()
    logger(f"[SNIFF] {summary}")


def start_sniffing(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    output: Optional[str] = None,
    count: int = 0,
    packet_handler: Optional[Callable[[Packet], None]] = None
) -> bool:
    """
    Démarre la capture de paquets avec les paramètres spécifiés.
    
    Args:
        interface: Interface réseau à écouter (None pour toutes les interfaces)
        bpf_filter: Chaîne de filtrage BPF pour filtrer les paquets
        output: Chemin du fichier de sortie pour sauvegarder les paquets capturés
        count: Nombre de paquets à capturer (0 pour illimité)
        packet_handler: Fonction personnalisée de traitement des paquets
        
    Returns:
        bool: True si la capture s'est terminée avec succès, False sinon
        
    Raises:
        PermissionError: Lorsque l'exécution se fait sans privilèges suffisants
        ValueError: Lorsque des paramètres invalides sont fournis
    """
    if count < 0:
        raise ValueError("Count must be non-negative")
    
    if output and not output.endswith(('.pcap', '.cap')):
        logger("[!] Warning: Output file should have .pcap or .cap extension")
    
    handler = packet_handler or packet_callback
    
    try:
        logger("[*] Starting packet sniffer...")
        logger(f"[*] Interface: {interface or 'all'}")
        logger(f"[*] Filter: {bpf_filter or 'none'}")
        logger(f"[*] Count: {count or 'unlimited'}")
        
        stop_event.clear()

        packets = sniff(
            iface=interface,
            filter=bpf_filter,
            prn=handler,
            count=count,
            stop_filter=lambda pkt: stop_event.is_set()
        )

        
        if output:
            wrpcap(output, packets)
            logger(f"[+] {len(packets)} packets saved to {output}")
        
        logger(f"[+] Sniffing completed. Captured {len(packets)} packets")
        return True
        
    except PermissionError:
        logger("[!] Permission denied. Run as root or with sudo.")
        return False
    except KeyboardInterrupt:
        logger("[*] Sniffing interrupted by user")
        return True
    except Exception as e:
        logger(f"[!] Sniffing failed: {e}")
        return False


from threading import Event

stop_event = Event()

def stop_sniffing():
    """
    Déclenche l'arrêt du sniffing.
    """
    stop_event.set()
