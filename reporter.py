import json
import csv
import os

def generate_report(results, format='json', output_file=None):
    # Génère un rapport du scan dans le format demandé.
    if not output_file:
        output_file = f"scan_report.{format}"

    if format == 'json':
        _generate_json_report(results, output_file)
    elif format == 'csv':
        _generate_csv_report(results, output_file)
    elif format == 'md':
        _generate_markdown_report(results, output_file)
    elif format == 'html':
        _generate_html_report(results, output_file)
    else:
        raise ValueError("Format de rapport non supporté")

    print(f"[+] Rapport généré : {output_file}")



def _generate_json_report(results, output_file):
    formatted_results = {}
    for ip, data in results.items():
        port_list = data.get('ports', [])  
        formatted_ports = [
            {'port': str(port), 'protocol': 'tcp', 'service': '', 'banner': ''} for port in port_list
        ]
        formatted_results[ip] = formatted_ports
    with open(output_file, 'w') as f:
        json.dump(formatted_results, f, indent=4)

def _generate_csv_report(results, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP', 'Port', 'Protocol', 'Service', 'Banner']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ip, data in results.items():
                port_list = data['ports']  
                for port in port_list:
                    port_info = {
                        'port': str(port),  
                        'protocol': 'tcp',
                        'service': '',
                        'banner': ''
                    }
                    writer.writerow({
                        'IP': ip,
                        'Port': port_info['port'],
                        'Protocol': port_info['protocol'],
                        'Service': port_info['service'],
                        'Banner': port_info['banner']
                    })
            

def _generate_markdown_report(results, output_file):
    with open(output_file, 'w') as f:
        f.write("# Rapport de Scan Réseau\n\n")
        for ip, data in results.items():
            f.write(f"## Hôte : {ip}\n\n")
            f.write("| Port | Protocole | Service | Bannière |\n")
            f.write("|------|-----------|---------|----------|\n")
            
            port_list = data['ports']  
            for port in port_list:
                    port_info = {
                        'port': str(port),  
                        'protocol': 'tcp',
                        'service': '',
                        'banner': ''
                    }
                    f.write(f"| {port_info['port']} | {port_info['protocol']} | "
                            f"{port_info['service']} | {port_info['banner']} |\n")
            
            f.write("\n")

def _generate_html_report(results, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("<html><head><title>Rapport de Scan</title></head><body>")
        f.write("<h1>Rapport de Scan Réseau</h1>")
        for ip, data in results.items():
            f.write(f"<h2>Hôte : {ip}</h2>")
            f.write("<table border='1'><tr><th>Port</th><th>Protocole</th><th>Service</th><th>Bannière</th></tr>")
            
            port_list = data['ports']  
            for port in port_list:
                    port_info = {
                        'port': str(port),  
                        'protocol': 'tcp',
                        'service': '',
                        'banner': ''
                    }
                    f.write(f"<tr><td>{port_info['port']}</td><td>{port_info['protocol']}</td>"
                            f"<td>{port_info['service']}</td><td>{port_info['banner']}</td></tr>")
            
            f.write("</table><br>")
        f.write("</body></html>")