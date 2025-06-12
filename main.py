import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scanner import scan_targets
from banner_grabber import grab_banners
from sniffer import start_sniffing, stop_event
from reporter import generate_report
from utils import validate_ip, parse_ports
import threading
import io
import sys
import argparse

class RedirectText(object):
    def __init__(self, text_ctrl):
        self.output = text_ctrl

    def write(self, string):
        self.output.insert(tk.END, string)
        self.output.see(tk.END)

    def flush(self):
        pass

def parse_args():
    parser = argparse.ArgumentParser(description="Pre-fill GUI fields for scanning or sniffing.")
    parser.add_argument("--target", help="Target IP(s)", default="127.0.0.1-127.0.0.4,127.0.0.5")
    parser.add_argument("--ports", help="Ports to scan", default="21,22,25,80,110,135,143,443,445")
    parser.add_argument("--udp", action="store_true", help="Use UDP")
    parser.add_argument("--grab_banner", action="store_true", default=True, help="Grab banners")
    parser.add_argument("--report", choices=["json", "csv", "md", "html"], help="Report format", default="html")
    parser.add_argument("--delay", type=int, help="Delay between scans (sec)", default=0)
    parser.add_argument("--interface", help="Sniffer interface", default="Wi-Fi")
    parser.add_argument("--filter", help="BPF filter", default="tcp port 443")
    parser.add_argument("--output", help="Output .pcap file", default="sniff_output.pcap")
    parser.add_argument("--max_packets", type=int, help="Max packets to capture")
    parser.add_argument("--timeout", type=int, help="Timeout per port (sec)", default=2)
    parser.add_argument("--threads", type=int, help="Number of concurrent threads", default=1)
    parser.add_argument("--exclude", help="Comma-separated IPs to exclude", default="127.0.0.2")
    parser.add_argument("--verbose", action="store_true", default=True, help="Enable verbose output")
    return parser.parse_args()

def run_scan(target, ports, udp, grab_banner, report_format, delay, output_widget,
             timeout, threads, exclude, verbose):

    sys.stdout = RedirectText(output_widget)
    sys.stderr = RedirectText(output_widget)

    try:
        targets = target.split(',')
        ports = parse_ports(ports)
        exclude_ips = [ip.strip() for ip in exclude.split(',') if ip.strip()]
        results = scan_targets(
            targets, ports, udp=udp, delay=delay,
            timeout=timeout, threads=threads,
            exclude=exclude_ips, verbose=verbose
        )

        if grab_banner:
            banners = grab_banners(results)
            for ip in results:
                results[ip]["banners"] = banners.get(ip, {})

        if report_format and results:
            generate_report(results, format=report_format)

        print("[+] Scanning complete.\r\n")
    except Exception as e:
        print(f"[!] Scan Error: {e}")

def run_sniffer_button(interface, bpf_filter, output, max_packets, output_widget, start_button, stop_button):
    def _run():
        start_button.config(state='disabled')
        stop_button.config(state='normal')
        stop_event.clear()
        run_sniffer(interface, bpf_filter, output, max_packets, output_widget)
        start_button.config(state='normal')
        stop_button.config(state='disabled')

    threading.Thread(target=_run).start()

def stop_sniffer_button(start_button, stop_button):
    stop_event.set()
    start_button.config(state='normal')
    stop_button.config(state='disabled')

def run_sniffer(interface, bpf_filter, output, max_packets, output_widget):
    sys.stdout = RedirectText(output_widget)
    sys.stderr = RedirectText(output_widget)

    try:
        count = int(max_packets) if max_packets else 0
    except ValueError:
        count = 0

    start_sniffing(interface=interface, bpf_filter=bpf_filter, output=output, count=count)
    print("[+] Packet capture complete.")

def create_gui(args):
    root = tk.Tk()
    root.title("Python Network Pentest Tool")

    notebook = ttk.Notebook(root)
    scan_frame = ttk.Frame(notebook)
    sniff_frame = ttk.Frame(notebook)
    notebook.add(scan_frame, text="Scan")
    notebook.add(sniff_frame, text="Sniff")
    notebook.pack(fill='both', expand=True)

    output_box = tk.Text(root, wrap='word', height=15)
    output_box.pack(fill='both', expand=True, padx=5, pady=5)

    clear_button = ttk.Button(root, text="Clear Output", command=lambda: output_box.delete('1.0', tk.END))
    clear_button.pack(pady=5)

    # Scan Tab
    # Targets
    ttk.Label(scan_frame, text="Target").grid(row=0, column=0, sticky='w')
    target_entry = ttk.Entry(scan_frame, width=40)
    target_entry.insert(0, args.target)
    target_entry.grid(row=0, column=1)

    # Ports
    ttk.Label(scan_frame, text="Ports").grid(row=1, column=0, sticky='w')
    ports_entry = ttk.Entry(scan_frame, width=40)
    ports_entry.insert(0, args.ports)
    ports_entry.grid(row=1, column=1)

    # UDP scan toggle
    udp_var = tk.BooleanVar()
    udp_var.set(args.udp)
    ttk.Checkbutton(scan_frame, text="UDP Scan", variable=udp_var).grid(row=2, column=1, sticky='w')

    # Banner grabbing toggle/choice
    grab_banner_var = tk.BooleanVar()
    grab_banner_var.set(args.grab_banner)
    ttk.Checkbutton(scan_frame, text="Grab Banners", variable=grab_banner_var).grid(row=3, column=1, sticky='w')

    # Report format
    ttk.Label(scan_frame, text="Report Format").grid(row=4, column=0, sticky='w')
    report_format = ttk.Combobox(scan_frame, values=["json", "csv", "md", "html"])
    report_format.set(args.report if args.report else "")
    report_format.grid(row=4, column=1)

    # Delay between scans
    ttk.Label(scan_frame, text="Delay (sec)").grid(row=5, column=0, sticky='w')
    delay_entry = ttk.Entry(scan_frame, width=10)
    delay_entry.insert(0, str(args.delay))
    delay_entry.grid(row=5, column=1, sticky='w')

    # Timeout per port
    ttk.Label(scan_frame, text="Timeout (sec)").grid(row=6, column=0, sticky='w')
    timeout_entry = ttk.Entry(scan_frame, width=10)
    timeout_entry.insert(0, str(args.timeout))
    timeout_entry.grid(row=6, column=1, sticky='w')

    # Number of threads
    ttk.Label(scan_frame, text="Threads").grid(row=7, column=0, sticky='w')
    threads_entry = ttk.Entry(scan_frame, width=10)
    threads_entry.insert(0, str(args.threads))
    threads_entry.grid(row=7, column=1, sticky='w')

    # Exclude IPs
    ttk.Label(scan_frame, text="Exclude IPs").grid(row=8, column=0, sticky='w')
    exclude_entry = ttk.Entry(scan_frame, width=40)
    exclude_entry.insert(0, args.exclude)
    exclude_entry.grid(row=8, column=1)

    # Verbose
    verbose_var = tk.BooleanVar()
    verbose_var.set(args.verbose)
    ttk.Checkbutton(scan_frame, text="Verbose Output", variable=verbose_var).grid(row=9, column=1, sticky='w')

    # Start button
    ttk.Button(scan_frame, text="Start Scan", command=lambda: threading.Thread(target=run_scan, args=(
        target_entry.get(),
        ports_entry.get(),
        udp_var.get(),
        grab_banner_var.get(),
        report_format.get(),
        int(delay_entry.get()) if delay_entry.get().isdigit() else 0,
        output_box,
        int(timeout_entry.get()) if timeout_entry.get().isdigit() else 2,
        int(threads_entry.get()) if threads_entry.get().isdigit() else 10,
        exclude_entry.get(),
        verbose_var.get()
    )).start()).grid(row=11, column=1, pady=10)


    # SNIFF TAB WIDGETS
    ttk.Label(sniff_frame, text="Interface (all = keep field empty)").grid(row=0, column=0, sticky='w')
    interface_entry = ttk.Entry(sniff_frame, width=40)
    interface_entry.insert(0, args.interface)
    interface_entry.grid(row=0, column=1)

    ttk.Label(sniff_frame, text="BPF Filter").grid(row=1, column=0, sticky='w')
    filter_entry = ttk.Entry(sniff_frame, width=40)
    filter_entry.insert(0, args.filter)
    filter_entry.grid(row=1, column=1)

    ttk.Label(sniff_frame, text="Output File").grid(row=2, column=0, sticky='w')
    output_entry = ttk.Entry(sniff_frame, width=40)
    output_entry.insert(0, args.output)
    output_entry.grid(row=2, column=1)

    ttk.Label(sniff_frame, text="Max Packets").grid(row=3, column=0, sticky='w')
    max_packets_entry = ttk.Entry(sniff_frame, width=10)
    max_packets_entry.insert(0, str(args.max_packets))
    max_packets_entry.grid(row=3, column=1, sticky='w')

    start_sniff_btn = ttk.Button(sniff_frame, text="Start Sniffing")
    start_sniff_btn.grid(row=4, column=1, pady=10)

    stop_sniff_btn = ttk.Button(sniff_frame, text="Stop Sniffing")
    stop_sniff_btn.grid(row=5, column=1, pady=10)
    stop_sniff_btn.config(state='disabled')

    start_sniff_btn.config(command=lambda: run_sniffer_button(
        interface_entry.get(),
        filter_entry.get(),
        output_entry.get(),
        max_packets_entry.get(),
        output_box,
        start_sniff_btn,
        stop_sniff_btn
    ))

    stop_sniff_btn.config(command=lambda: stop_sniffer_button(start_sniff_btn, stop_sniff_btn))

    root.mainloop()

if __name__ == "__main__":
    args = parse_args()
    create_gui(args)
