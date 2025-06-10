import argparse
from scanner import scan_targets
from banner_grabber import grab_banners
from sniffer import start_sniffer
from reporter import generate_report
from utils import validate_ip, parse_ports


def main():
    parser = argparse.ArgumentParser(description="Python Network Scanner")

    parser.add_argument("--target", help="Target IP, subnet, or comma-separated list")
    parser.add_argument("--ports", help="Ports to scan (e.g., 22,80,443 or 20-100)")
    parser.add_argument("--udp", action="store_true", help="Use UDP scan instead of TCP")
    parser.add_argument("--grab-banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("--sniff", action="store_true", help="Enable passive sniffer mode")
    parser.add_argument("--interface", help="Network interface to sniff on")
    parser.add_argument("--filter", help="BPF filter for packet sniffer (e.g., 'tcp port 80')")
    parser.add_argument("--output", help="Output file for sniffer capture (e.g., capture.pcap)")
    parser.add_argument("--report", choices=['json', 'csv', 'md', 'html'], help="Report format")
    parser.add_argument("--delay", type=int, help="Delay between scans (in seconds)")

    args = parser.parse_args()

    results = {}

    if args.sniff:
        start_sniffer(interface=args.interface, bpf_filter=args.filter, output_file=args.output)

    if args.target and args.ports:
        targets = args.target.split(',')
        ports = parse_ports(args.ports)

        results = scan_targets(targets, ports, udp=args.udp, delay=args.delay)

        if args.grab_banner:
            banners = grab_banners(results)
            results = {ip: {**results[ip], 'banners': banners.get(ip, {})} for ip in results}

    elif args.grab_banner:
        # Only banner grabbing, assumes ports + target are provided
        targets = args.target.split(',')
        ports = parse_ports(args.ports)
        results = grab_banners({t: {"ports": ports} for t in targets})

    if args.report and results:
        generate_report(results, format=args.report)


if __name__ == "__main__":
    main()
