"""
Packet sniffer module using Scapy.

This module provides functionality to capture and analyze network packets.
"""

from typing import Optional, Callable
from scapy.all import sniff, wrpcap, Packet
from utils import logger


def packet_callback(packet: Packet) -> None:
    """
    Process captured packets and log their summary.
    
    Args:
        packet: The captured network packet
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
    Start packet sniffing with specified parameters.
    
    Args:
        interface: Network interface to sniff on (None for all interfaces)
        bpf_filter: BPF filter string for packet filtering
        output: Output file path to save captured packets
        count: Number of packets to capture (0 for unlimited)
        packet_handler: Custom packet processing function
        
    Returns:
        bool: True if sniffing completed successfully, False otherwise
        
    Raises:
        PermissionError: When running without sufficient privileges
        ValueError: When invalid parameters are provided
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
        
        packets = sniff(
            iface=interface,
            filter=bpf_filter,
            prn=handler,
            count=count
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
