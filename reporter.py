import json
import csv
from datetime import datetime

def generate_report(results, format='json', output_file=None):
    """
    Génère un rapport du scan dans le format demandé.
    
    Args:
        results (dict): Résultats du scan {IP: {'ports': [port1, port2, ...]}}
        format (str): Format de sortie ('json', 'csv', 'md', 'html')
        output_file (str): Nom du fichier de sortie (optionnel)
    """
    if not results:
        print("[-] Aucun résultat à exporter")
        return
    
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"scan_report_{timestamp}.{format}"

    try:
        if format == 'json':
            _generate_json_report(results, output_file)
        elif format == 'csv':
            _generate_csv_report(results, output_file)
        elif format == 'md':
            _generate_markdown_report(results, output_file)
        elif format == 'html':
            _generate_html_report(results, output_file)
        else:
            raise ValueError(f"Format de rapport non supporté: {format}")

        print(f"[+] Rapport généré : {output_file}")
        
    except Exception as e:
        print(f"[-] Erreur lors de la génération du rapport : {e}")

def _generate_json_report(results, output_file):
    """Génère un rapport JSON avec métadonnées."""
    report_data = {
        'scan_info': {
            'timestamp': datetime.now().isoformat(),
            'total_hosts': len(results),
            'total_open_ports': sum(len(data.get('ports', [])) for data in results.values())
        },
        'results': {}
    }
    
    for ip, data in results.items():
        port_list = data.get('ports', [])
        formatted_ports = []
        
        for port in port_list:
            port_info = {
                'port': int(port),
                'protocol': 'tcp',
                'service': data.get('services', {}).get(str(port), ''),
                'banner': data.get('banners', {}).get(str(port), '')
            }
            formatted_ports.append(port_info)
        
        report_data['results'][ip] = {
            'status': 'up' if port_list else 'down',
            'open_ports': len(port_list),
            'ports': formatted_ports
        }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

def _generate_csv_report(results, output_file):
    """Génère un rapport CSV."""
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['IP', 'Port', 'Protocol', 'Service', 'Banner', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for ip, data in results.items():
            port_list = data.get('ports', [])
            
            if not port_list:
                # Écrire une ligne même si aucun port n'est ouvert
                writer.writerow({
                    'IP': ip,
                    'Port': 'N/A',
                    'Protocol': 'N/A',
                    'Service': 'No open ports',
                    'Banner': '',
                    'Timestamp': timestamp
                })
            else:
                for port in port_list:
                    writer.writerow({
                        'IP': ip,
                        'Port': str(port),
                        'Protocol': 'tcp',
                        'Service': data.get('services', {}).get(str(port), ''),
                        'Banner': data.get('banners', {}).get(str(port), ''),
                        'Timestamp': timestamp
                    })

def _generate_markdown_report(results, output_file):
    """Génère un rapport Markdown."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# 🔍 Rapport de Scan Réseau\n\n")
        f.write(f"**Date du scan :** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Nombre d'hôtes scannés :** {len(results)}\n\n")
        
        total_ports = sum(len(data.get('ports', [])) for data in results.values())
        f.write(f"**Total des ports ouverts :** {total_ports}\n\n")
        f.write("---\n\n")
        
        for ip, data in results.items():
            port_list = data.get('ports', [])
            f.write(f"## 🖥️ Hôte : {ip}\n\n")
            
            if not port_list:
                f.write("*Aucun port ouvert détecté*\n\n")
                continue
            
            f.write(f"**Ports ouverts :** {len(port_list)}\n\n")
            f.write("| Port | Protocole | Service | Bannière |\n")
            f.write("|------|-----------|---------|----------|\n")
            
            for port in port_list:
                service = data.get('services', {}).get(str(port), 'Unknown')
                banner = data.get('banners', {}).get(str(port), '')
                f.write(f"| {port} | tcp | {service} | {banner} |\n")
            
            f.write("\n")

def _generate_html_report(results, output_file):
    """Génère un rapport HTML avec CSS intégré."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan Réseau</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .no-ports { color: #7f8c8d; font-style: italic; }
        .port-open { color: #27ae60; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">""")
        
        f.write("<h1>🔍 Rapport de Scan Réseau</h1>")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_ports = sum(len(data.get('ports', [])) for data in results.values())
        
        f.write(f"""<div class="info">
            <strong>Date du scan :</strong> {timestamp}<br>
            <strong>Nombre d'hôtes scannés :</strong> {len(results)}<br>
            <strong>Total des ports ouverts :</strong> {total_ports}
        </div>""")
        
        for ip, data in results.items():
            port_list = data.get('ports', [])
            f.write(f"<h2>🖥️ Hôte : {ip}</h2>")
            
            if not port_list:
                f.write('<p class="no-ports">Aucun port ouvert détecté</p>')
                continue
            
            f.write(f"<p><strong>Ports ouverts :</strong> <span class='port-open'>{len(port_list)}</span></p>")
            f.write("<table><tr><th>Port</th><th>Protocole</th><th>Service</th><th>Bannière</th></tr>")
            
            for port in port_list:
                service = data.get('services', {}).get(str(port), 'Unknown')
                banner = data.get('banners', {}).get(str(port), '')
                f.write(f"<tr><td class='port-open'>{port}</td><td>tcp</td><td>{service}</td><td>{banner}</td></tr>")
            
            f.write("</table>")
            
        f.write("""    </div>
</body>
</html>""")


