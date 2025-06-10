import ipaddress
import logging
from time import time, sleep

# --- Logger Setup ---
logging.basicConfig(level=logging.INFO, format='%(message)s')

def logger(message):
    logging.info(message)

# --- IP Validation ---
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# --- Port Parser ---
def parse_ports(ports_str):
    ports = set()
    parts = ports_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# --- Timer Utility ---
def timer(func):
    def wrapper(*args, **kwargs):
        start = time()
        result = func(*args, **kwargs)
        end = time()
        logger(f"[TIMER] {func.__name__} executed in {end - start:.2f}s")
        return result
    return wrapper
