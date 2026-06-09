import subprocess
import platform
import argparse
import time
import re
import html
import datetime
import sys
import json
import csv
import io

Version = "1.0.1"

parser = argparse.ArgumentParser(description="LightSave : Light-Scan Scans Saving Tool")
parser.add_argument("-C", required=True, help="Lightscan command")
parser.add_argument("-S", default="txt", choices=["txt", "light", "html", "xml", "csv", "json"],
                    help="Saving Format (txt,light,html,xml,csv,json)")
args = parser.parse_args()

current = time.localtime()
filename = f"Lightscan_Output_{time.strftime('%Y-%m-%d_%H-%M-%S', current)}.{args.S.lower()}"


def parse_scan_output(output):
    results = {
        'target': None,
        'scan_type': None,
        'open_ports': [],
        'closed_ports': [],
        'closed_ports_count': 0,
        'filtered_ports': [],
        'filtered_ports_count': 0,
        'os_fingerprint': None,
        'firewall_status': None,
        'firewall_detected': None,
        'scan_time': None,
        'scan_date': datetime.datetime.now().isoformat(),
        'version': None,
        'banners': [],
        'lsse_scripts': [],
        'lsse_response': None,
        'lsse_scripts_detected': [],
        'mac_address': None,
        'ip_status': None,
        'host_status': None
    }

    version_match = re.search(r'Version : ([\d\.]+)', output)
    if version_match:
        results['version'] = version_match.group(1)

    host_match = re.search(r'\[ECHO\] Host (.+?) is (up|down)!', output)
    if host_match:
        results['host_status'] = host_match.group(2)
        if not results['target']:
            results['target'] = host_match.group(1)

    target_match = re.search(r'\[\+\] Scan result for : (.+)', output)
    if target_match:
        results['target'] = target_match.group(1)

    ip_status_match = re.search(r'\[\+\] IP Status: (.+)', output)
    if ip_status_match:
        results['ip_status'] = ip_status_match.group(1)

    mac_match = re.search(r'\[\+\] Mac Address: ([0-9a-fA-F:]+)', output)
    if mac_match:
        results['mac_address'] = mac_match.group(1)

    type_match = re.search(r'Scan Type: (.+) \|', output)
    if type_match:
        results['scan_type'] = type_match.group(1)

    open_section = re.search(r'\[\+\] Open Ports: (\d+)(.*?)(?=\[\+\] Closed Ports:|$)', output, re.DOTALL)
    if open_section:
        results['open_ports_count'] = int(open_section.group(1))
        open_text = open_section.group(2)

        port_matches = re.findall(r'Port (\d+) ([^\s]+)', open_text)
        for port, service in port_matches:
            results['open_ports'].append({'port': port, 'service': service.strip()})

    closed_match = re.search(r'\[\+\] Closed Ports: (\d+)', output)
    if closed_match:
        results['closed_ports_count'] = int(closed_match.group(1))

    filtered_match = re.search(r'\[\+\] Filtered Ports: (\d+)', output)
    if filtered_match:
        results['filtered_ports_count'] = int(filtered_match.group(1))

    banner_section = re.search(
        r'\[\+\] Captured Banner/s: (\d+)\s*(.*?)(?=\[\+\] OS Fingerprint Results:|\[\+\] Lightscan scanned|$)',
        output, re.DOTALL)
    if banner_section:
        banner_count = int(banner_section.group(1))
        banner_text = banner_section.group(2)

        banner_matches = re.findall(r'\[\*\] Banner from Port (\d+):\s*=+\s*(.*?)\s*=+', banner_text, re.DOTALL)
        for port, banner_content in banner_matches:
            results['banners'].append({
                'port': port,
                'content': banner_content.strip()
            })

    firewall_section = re.search(
        r'\[\!\] Firewall Analysis for .+?:\s*(.*?)(?=\[\+\] Captured Banner/s:|\[\+\] OS Fingerprint Results:|\[\+\] Lightscan scanned|$)',
        output, re.DOTALL)
    if firewall_section:
        firewall_text = firewall_section.group(1)

        conclusion_match = re.search(r'\[\+\] (.+?)(?=\n|$)', firewall_text)
        if conclusion_match:
            conclusion = conclusion_match.group(1).strip()
            results['firewall_status'] = conclusion

            if 'STRONG FIREWALL DETECTED' in conclusion:
                results['firewall_detected'] = 'STRONG'
            elif 'NO FIREWALL DETECTED' in conclusion:
                results['firewall_detected'] = 'NONE'
            elif 'WEAK FIREWALL' in conclusion:
                results['firewall_detected'] = 'WEAK'
            else:
                results['firewall_detected'] = 'UNKNOWN'

    os_match = re.search(r'\[\+\] OS Fingerprint .*?\[\+\] (.+?) :\s+(\d+\.?\d*)%', output, re.DOTALL)
    if os_match:
        results['os_fingerprint'] = {'os': os_match.group(1), 'confidence': os_match.group(2)}

    time_match = re.search(r'\[\*\] Scan completed in ([\d\.]+) seconds', output)
    if time_match:
        results['scan_time'] = time_match.group(1)

    lsse_response_match = re.search(r'\[\+\] LSSE Response for (.+?):', output)
    if lsse_response_match:
        results['lsse_response'] = lsse_response_match.group(1)

    return results


def generate_csv(data, raw_output):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['#' * 60])
    writer.writerow(['# LightScan Security Report'])
    writer.writerow(['# Generated by LightSave v' + Version])
    writer.writerow(['# Generated on: ' + data.get('scan_date', 'Unknown')])
    writer.writerow(['#' * 60])
    writer.writerow([])

    writer.writerow(['[SCAN INFORMATION]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Parameter', 'Value'])
    writer.writerow(['Target', data.get('target', 'Unknown')])
    writer.writerow(['Scan Type', data.get('scan_type', 'Unknown')])
    writer.writerow(['Scan Duration (seconds)', data.get('scan_time', '0')])
    writer.writerow(['IP Status', data.get('ip_status', 'Unknown')])
    writer.writerow(['MAC Address', data.get('mac_address', 'Unknown')])
    writer.writerow(['Host Status', data.get('host_status', 'Unknown')])
    writer.writerow(['LightScan Version', data.get('version', 'Unknown')])
    writer.writerow([])

    writer.writerow(['[FIREWALL ANALYSIS]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Status', data.get('firewall_status', 'Unknown')])
    writer.writerow(['Detection Method', data.get('firewall_detected', 'Unknown')])
    writer.writerow([])

    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    writer.writerow(['[SCAN STATISTICS]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Metric', 'Count'])
    writer.writerow(['Total Ports Scanned', total])
    writer.writerow(['Open Ports', len(data.get('open_ports', []))])
    writer.writerow(['Closed Ports', data.get('closed_ports_count', 0)])
    writer.writerow(['Filtered Ports', data.get('filtered_ports_count', 0)])

    if total > 0:
        open_pct = (len(data.get('open_ports', [])) / total) * 100
        writer.writerow(['Open Ports Percentage', f'{open_pct:.1f}%'])
    writer.writerow([])

    if data.get('os_fingerprint') and data['os_fingerprint'].get('os'):
        writer.writerow(['[OS FINGERPRINT]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Detected Operating System', data['os_fingerprint'].get('os', 'Unknown')])
        writer.writerow(['Confidence Score', f"{data['os_fingerprint'].get('confidence', '0')}%"])
        writer.writerow([])


    writer.writerow(['[OPEN PORTS SUMMARY]'])
    writer.writerow(['-' * 40])
    if data.get('open_ports'):
        writer.writerow(['Port', 'Service', 'Status', 'Banner (truncated)'])
        writer.writerow(['----', '-------', '------', '----------------'])
        for port in data.get('open_ports', []):
            banner = next((b['content'] for b in data.get('banners', []) if str(b['port']) == str(port['port'])), '')
            clean_banner = banner.replace('\n', ' ').replace('\r', '')[:200]
            writer.writerow([port['port'], port['service'], 'OPEN', clean_banner if clean_banner else '(no banner)'])
    else:
        writer.writerow(['No open ports found'])
    writer.writerow([])

    if data.get('closed_ports'):
        writer.writerow(['[CLOSED PORTS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port'])
        for port in data['closed_ports']:
            writer.writerow([port])
        writer.writerow([])

    if data.get('filtered_ports'):
        writer.writerow(['[FILTERED PORTS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port'])
        for port in data['filtered_ports']:
            writer.writerow([port])
        writer.writerow([])

    if data.get('banners'):
        writer.writerow(['[BANNER CAPTURE DETAILS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port', 'Full Banner Content'])
        writer.writerow(['----', '--------------------'])
        for banner in data['banners']:
            clean_banner = banner['content'].replace('\n', ' ').replace('\r', '')[:500]
            writer.writerow([banner['port'], clean_banner])
        writer.writerow([])

    if data.get('lsse_response') or data.get('lsse_scripts_detected') or data.get('lsse_scripts'):
        writer.writerow(['[LSSE SCRIPT ENGINE RESULTS]'])
        writer.writerow(['-' * 40])

        if data.get('lsse_response'):
            writer.writerow(['Target URL/Host', data['lsse_response']])

        if data.get('lsse_scripts_detected'):
            writer.writerow(['\n[JavaScript Files Detected]'])
            writer.writerow(['#', 'Script Source'])
            for idx, script in enumerate(data['lsse_scripts_detected'], 1):
                clean_script = script[:300].replace('\n', ' ').replace('\r', '')
                writer.writerow([f'#{idx}', clean_script + ('...' if len(script) > 300 else '')])

        for script in data.get('lsse_scripts', []):
            if script.get('type') == 'subdomain':
                writer.writerow(['\n[Subdomain Discovered]'])
                writer.writerow(['Subdomain', script.get('name', 'Unknown')])
                writer.writerow(['IP Address', script.get('ip', 'Unknown')])
            elif script.get('type') == 'ssl_cert':
                writer.writerow(['\n[SSL/TLS Certificate Info]'])
                for key, value in script.get('data', {}).items():
                    writer.writerow([f'  {key}', str(value)[:200]])
            elif script.get('type') == 'http_title':
                writer.writerow(['\n[HTTP Page Titles]'])
                writer.writerow(['Page Title'])
                for title in script.get('titles', []):
                    writer.writerow([title])
            elif script.get('type') == 'robots':
                writer.writerow(['\n[Robots.txt Entries]'])
                writer.writerow(['Disallowed Paths'])
                for path in script.get('disallowed', []):
                    writer.writerow([path])
            elif script.get('type') == 'cert_info':
                writer.writerow(['\n[Certificate Information]'])
                for key, value in script.get('data', {}).items():
                    writer.writerow([f'  {key}', str(value)[:200]])

        writer.writerow([])

    writer.writerow(['#' * 60])
    writer.writerow(['# RAW SCANNER OUTPUT'])
    writer.writerow(['#' * 60])
    writer.writerow([])


    if raw_output:
        for line in raw_output.split('\n'):
            if line.strip():
                writer.writerow([line])
            else:
                writer.writerow([''])
    else:
        writer.writerow(['(No raw output available)'])

    writer.writerow([])
    writer.writerow(['#' * 60])
    writer.writerow(['# End of Report'])
    writer.writerow(['#' * 60])

    return output.getvalue()


def generate_json(data, raw_output):
    lsse_scripts_processed = []
    for script in data.get('lsse_scripts', []):
        if script.get('type') == 'subdomain':
            lsse_scripts_processed.append({
                'type': 'subdomain',
                'subdomain': script.get('name'),
                'ip': script.get('ip')
            })
        elif script.get('type') == 'ssl_cert':
            lsse_scripts_processed.append({
                'type': 'ssl_certificate',
                'certificate_data': script.get('data', {})
            })
        elif script.get('type') == 'http_title':
            lsse_scripts_processed.append({
                'type': 'http_titles',
                'titles': script.get('titles', [])
            })
        elif script.get('type') == 'robots':
            lsse_scripts_processed.append({
                'type': 'robots_txt',
                'disallowed_paths': script.get('disallowed', []),
                'sitemaps': script.get('sitemaps', [])
            })
        elif script.get('type') == 'cert_info':
            lsse_scripts_processed.append({
                'type': 'certificate_info',
                'details': script.get('data', {})
            })
        elif script.get('type') == 'http_dir':
            lsse_scripts_processed.append({
                'type': 'directory_bruteforce',
                'found_directories': script.get('directories', []),
                'wordlist_used': script.get('wordlist'),
                'total_tested': script.get('total_tested', 0)
            })

    closed_ports_list = data.get('closed_ports', [])
    filtered_ports_list = data.get('filtered_ports', [])

    open_ports_enriched = []
    for port in data.get('open_ports', []):
        port_num = port.get('port')
        banner_info = next((b for b in data.get('banners', []) if str(b.get('port')) == str(port_num)), None)

        open_ports_enriched.append({
            'port': port_num,
            'service': port.get('service'),
            'status': 'OPEN',
            'banner': banner_info.get('content') if banner_info else None,
            'banner_length': len(banner_info.get('content', '')) if banner_info else 0
        })

    json_data = {
        'metadata': {
            'version': data.get('version'),
            'scan_date': data.get('scan_date'),
            'target': data.get('target'),
            'scan_type': data.get('scan_type'),
            'scan_time_seconds': float(data.get('scan_time', 0)) if data.get('scan_time') else None,
            'ip_status': data.get('ip_status'),
            'mac_address': data.get('mac_address'),
            'host_status': data.get('host_status'),
            'lightscan_version': data.get('version')
        },
        'firewall_analysis': {
            'status': data.get('firewall_status'),
            'detection_method': data.get('firewall_detected'),
            'firewall_detected': data.get(
                'firewall_status') != 'NO FIREWALL DETECTED : no such filtered or open | filtered ports'
        } if data.get('firewall_status') else None,
        'os_fingerprint': data.get('os_fingerprint'),
        'statistics': {
            'total_ports_scanned': len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get(
                'filtered_ports_count', 0),
            'open_ports_count': len(data.get('open_ports', [])),
            'closed_ports_count': data.get('closed_ports_count', 0),
            'filtered_ports_count': data.get('filtered_ports_count', 0),
            'open_ports_percentage': round((len(data.get('open_ports', [])) / max(1, len(data.get('open_ports',
                                                                                                  [])) + data.get(
                'closed_ports_count', 0) + data.get('filtered_ports_count', 0))) * 100, 2)
        },
        'open_ports': open_ports_enriched,
        'closed_ports': closed_ports_list if closed_ports_list else None,
        'filtered_ports': filtered_ports_list if filtered_ports_list else None,
        'banners_captured': data.get('banners', []),
        'lsse_results': {
            'target': data.get('lsse_response'),
            'scripts_detected_count': len(data.get('lsse_scripts_detected', [])),
            'scripts_detected': data.get('lsse_scripts_detected', []),
            'script_results': lsse_scripts_processed if lsse_scripts_processed else None
        } if data.get('lsse_response') or lsse_scripts_processed else None,
        'raw_output': raw_output,
        'summary': {
            'success': len(data.get('open_ports', [])) > 0 or data.get('closed_ports_count', 0) > 0,
            'has_firewall': data.get(
                'firewall_status') != 'NO FIREWALL DETECTED : no such filtered or open | filtered ports' if data.get(
                'firewall_status') else None,
            'os_identified': data.get('os_fingerprint') is not None and data.get('os_fingerprint', {}).get(
                'os') is not None,
            'banners_found': len(data.get('banners', []))
        }
    }

    def clean_none(obj):
        if isinstance(obj, dict):
            return {k: clean_none(v) for k, v in obj.items() if v is not None}
        elif isinstance(obj, list):
            return [clean_none(item) for item in obj]
        else:
            return obj

    json_data = clean_none(json_data)

    return json.dumps(json_data, indent=2, ensure_ascii=False)


def stream_output(process, output_lines):
    for line in iter(process.stdout.readline, ''):
        if line:
            print(line, end='')
            sys.stdout.flush()
            output_lines.append(line)
    for line in iter(process.stderr.readline, ''):
        if line:
            print(line, end='')
            sys.stderr.flush()
            output_lines.append(line)


def generate_html(data, raw_output):
    banners_html = ""
    if data['banners']:
        banners_html = f'''
        <div class="ports-section">
            <h2 class="section-title">📡 Captured Banners ({len(data['banners'])})</h2>
            <div class="banners-grid">
        '''
        for banner in data['banners']:
            banners_html += f'''
                <div class="banner-card">
                    <h3>🔌 Port {banner['port']}</h3>
                    <div class="banner-content">
                        <pre>{html.escape(banner['content'])}</pre>
                    </div>
                </div>
            '''
        banners_html += '''
            </div>
        </div>
        '''

    firewall_html = ""
    if data.get('firewall_status'):
        firewall_color = "#00ff41" if data.get('firewall_detected') == 'NONE' else "#ffaa00" if data.get(
            'firewall_detected') == 'WEAK' else "#ff4444"
        firewall_icon = "🛡️" if data.get('firewall_detected') == 'STRONG' else "🔓" if data.get(
            'firewall_detected') == 'NONE' else "⚠️"
        firewall_html = f'''
        <div class="ports-section">
            <h2 class="section-title">🛡️ Firewall Analysis</h2>
            <div class="info-card" style="border-color: {firewall_color};">
                <h3 style="color: {firewall_color};">{firewall_icon} {data['firewall_status']}</h3>
                <div class="firewall-stats">
                    <p>📊 Open: {len(data.get('open_ports', []))} | 🔴 Closed: {data.get('closed_ports_count', 0)} | 🟡 Filtered: {data.get('filtered_ports_count', 0)}</p>
                </div>
            </div>
        </div>
        '''

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Light-Scan Report - {data.get('target', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff41;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.85);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
        }}
        h1 {{ font-size: 2.5em; text-align: center; margin-bottom: 10px; text-shadow: 0 0 10px #00ff41; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .info-card {{
            background: rgba(0, 255, 65, 0.05);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 15px;
            transition: all 0.3s ease;
        }}
        .info-card:hover {{ transform: translateY(-3px); box-shadow: 0 5px 20px rgba(0, 255, 65, 0.2); background: rgba(0, 255, 65, 0.1); }}
        .info-card h3 {{ color: #00ff41; margin-bottom: 10px; font-size: 1.1em; }}
        .info-card p {{ color: #ccc; font-size: 1.2em; font-weight: bold; }}
        .section-title {{ font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #00ff41; margin-top: 30px; }}
        .ports-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .ports-table th, .ports-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        .ports-table th {{ background: rgba(0, 255, 65, 0.1); color: #00ff41; font-weight: bold; }}
        .ports-table tr:hover {{ background: rgba(0, 255, 65, 0.05); }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 5px; font-size: 0.85em; font-weight: bold; }}
        .badge-open {{ background: rgba(0, 255, 65, 0.2); color: #00ff41; border: 1px solid #00ff41; }}
        .badge-closed {{ background: rgba(255, 68, 68, 0.2); color: #ff4444; border: 1px solid #ff4444; }}
        .badge-filtered {{ background: rgba(255, 170, 0, 0.2); color: #ffaa00; border: 1px solid #ffaa00; }}
        .banner-card {{
            background: rgba(0, 255, 65, 0.03);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .banner-card h3 {{ color: #00ff41; margin-bottom: 10px; }}
        .banner-content pre {{
            background: #0a0a0a;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.85em;
            color: #ccc;
        }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ text-align: center; padding: 20px; background: rgba(0, 255, 65, 0.05); border-radius: 10px; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 10px; }}
        .firewall-stats {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid #333; }}
        .raw-output {{ background: #0a0a0a; border: 1px solid #333; border-radius: 10px; padding: 20px; margin-top: 30px; overflow-x: auto; }}
        .raw-output pre {{ color: #00ff41; font-family: 'Consolas', monospace; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 <span style="background: linear-gradient(90deg, #00ff41 0%, #008f1f 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">Light-Scan Security Report</span></h1>
        <div class="subtitle">Professional Network Security Assessment</div>

        <div class="info-grid">
            <div class="info-card"><h3>🎯 Target</h3><p>{data.get('target', 'Unknown')}</p></div>
            <div class="info-card"><h3>⚡ Scan Type</h3><p>{data.get('scan_type', 'Unknown')}</p></div>
            <div class="info-card"><h3>⏱️ Scan Duration</h3><p>{data.get('scan_time', 'N/A')} seconds</p></div>
            <div class="info-card"><h3>🖥️ Host Status</h3><p>{data.get('host_status', 'Unknown')}</p></div>
        </div>

        {firewall_html}

        <div class="ports-section">
            <h2 class="section-title">📊 Open Ports ({len(data.get('open_ports', []))})</h2>
            <table class="ports-table">
                <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
                <tbody>
                    {''.join([f'<tr><td>{p["port"]}</td><td>{p["service"]}</td><td><span class="badge badge-open">OPEN</span></td></tr>' for p in data.get('open_ports', [])]) or '<tr><td colspan="3">No open ports found</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="ports-section">
            <h2 class="section-title">📈 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-number" style="color: #00ff41;">{len(data.get('open_ports', []))}</div><div class="stat-label">🟢 Open Ports</div></div>
                <div class="stat-card"><div class="stat-number" style="color: #ff4444;">{data.get('closed_ports_count', 0)}</div><div class="stat-label">🔴 Closed Ports</div></div>
                <div class="stat-card"><div class="stat-number" style="color: #ffaa00;">{data.get('filtered_ports_count', 0)}</div><div class="stat-label">🟡 Filtered Ports</div></div>
            </div>
        </div>

        {banners_html}

        <div class="raw-output">
            <h3>📄 Raw Scan Output</h3>
            <pre>{html.escape(raw_output)}</pre>
        </div>

        <div class="footer">
            <p>Generated by Light-Save v{Version} | Light-Scan Security Tool | {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="color: #444">For authorized security testing only.</p>
        </div>
    </div>
</body>
</html>"""

    return html_template


def generate_xml(data, raw_output):
    if raw_output is None:
        raw_output = ""

    raw_output = str(raw_output) if raw_output is not None else ""

    prettified_output = '\n'.join(raw_output.splitlines())

    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>']

    xml_parts.append(
        f'<LightScanReport version="{data.get("version", "1.1.6")}" generated="{data.get("scan_date", datetime.datetime.now().isoformat())}">')

    xml_parts.append('  <ScanInfo>')
    xml_parts.append(f'    <Target>{html.escape(str(data.get("target", "Unknown")))}</Target>')
    xml_parts.append(f'    <ScanType>{html.escape(str(data.get("scan_type", "Unknown")))}</ScanType>')
    xml_parts.append(f'    <Duration>{data.get("scan_time", "0")} seconds</Duration>')
    xml_parts.append(f'    <Timestamp>{data.get("scan_date", "")}</Timestamp>')
    xml_parts.append(f'    <IPStatus>{html.escape(str(data.get("ip_status", "Unknown")))}</IPStatus>')
    xml_parts.append(f'    <HostStatus>{html.escape(str(data.get("host_status", "Unknown")))}</HostStatus>')
    if data.get('mac_address'):
        xml_parts.append(f'    <MACAddress>{data["mac_address"]}</MACAddress>')
    xml_parts.append('  </ScanInfo>')

    if data.get('firewall_status'):
        xml_parts.append('  <FirewallAnalysis>')
        xml_parts.append(f'    <Status>{html.escape(str(data["firewall_status"]))}</Status>')
        xml_parts.append(f'    <Detection>{data.get("firewall_detected", "UNKNOWN")}</Detection>')
        xml_parts.append('  </FirewallAnalysis>')

    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    xml_parts.append('  <Statistics>')
    xml_parts.append(f'    <TotalPortsScanned>{total}</TotalPortsScanned>')
    xml_parts.append(f'    <OpenPorts>{len(data.get("open_ports", []))}</OpenPorts>')
    xml_parts.append(f'    <ClosedPorts>{data.get("closed_ports_count", 0)}</ClosedPorts>')
    xml_parts.append(f'    <FilteredPorts>{data.get("filtered_ports_count", 0)}</FilteredPorts>')
    xml_parts.append('  </Statistics>')

    if data.get('open_ports'):
        xml_parts.append(f'  <OpenPorts count="{len(data["open_ports"])}">')
        for port in data['open_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port.get("port", "unknown")}</Number>')
            xml_parts.append(f'      <Service>{html.escape(str(port.get("service", "unknown")))}</Service>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </OpenPorts>')

    if data.get('closed_ports'):
        xml_parts.append(f'  <ClosedPortsList count="{len(data["closed_ports"])}">')
        for port in data['closed_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port}</Number>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </ClosedPortsList>')

    if data.get('filtered_ports'):
        xml_parts.append(f'  <FilteredPortsList count="{len(data["filtered_ports"])}">')
        for port in data['filtered_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port}</Number>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </FilteredPortsList>')

    if data.get('banners'):
        xml_parts.append(f'  <CapturedBanners count="{len(data["banners"])}">')
        for banner in data['banners']:
            xml_parts.append('    <Banner>')
            xml_parts.append(f'      <Port>{banner.get("port", "unknown")}</Port>')
            content = banner.get("content", "")
            if content is None:
                content = ""
            xml_parts.append(f'      <Content><![CDATA[{content}]]></Content>')
            xml_parts.append('    </Banner>')
        xml_parts.append('  </CapturedBanners>')

    if data.get('os_fingerprint'):
        xml_parts.append('  <OSFingerprint>')
        xml_parts.append(
            f'    <DetectedOS>{html.escape(str(data["os_fingerprint"].get("os", "Unknown")))}</DetectedOS>')
        xml_parts.append(f'    <Confidence>{data["os_fingerprint"].get("confidence", "0")}%</Confidence>')
        xml_parts.append('  </OSFingerprint>')

    if data.get('lsse_response') or data.get('lsse_scripts'):
        xml_parts.append('  <LSSEResults>')
        if data.get('lsse_response'):
            xml_parts.append(f'    <Target>{html.escape(str(data["lsse_response"]))}</Target>')

        if data.get('lsse_scripts_detected'):
            xml_parts.append(f'    <DetectedScripts count="{len(data["lsse_scripts_detected"])}">')
            for idx, script in enumerate(data['lsse_scripts_detected']):
                if script is None:
                    script = ""
                xml_parts.append(f'      <Script index="{idx + 1}"><![CDATA[{script}]]></Script>')
            xml_parts.append('    </DetectedScripts>')

        for script in data.get('lsse_scripts', []):
            if script.get('type') == 'subdomain':
                xml_parts.append('    <Subdomain>')
                xml_parts.append(f'      <Name>{html.escape(str(script.get("name", "Unknown")))}</Name>')
                xml_parts.append(f'      <IP>{html.escape(str(script.get("ip", "Unknown")))}</IP>')
                xml_parts.append('    </Subdomain>')
            elif script.get('type') == 'ssl_cert':
                xml_parts.append('    <SSLCertificate>')
                for key, value in script.get('data', {}).items():
                    if value is None:
                        value = ""
                    key_clean = key.replace(' ', '').replace(':', '').replace('-', '')
                    xml_parts.append(f'      <{key_clean}>{html.escape(str(value))}</{key_clean}>')
                xml_parts.append('    </SSLCertificate>')
            elif script.get('type') == 'http_title':
                xml_parts.append('    <HTTPTitles>')
                for title in script.get('titles', []):
                    if title is None:
                        title = ""
                    xml_parts.append(f'      <Title>{html.escape(str(title))}</Title>')
                xml_parts.append('    </HTTPTitles>')

        xml_parts.append('  </LSSEResults>')

    if prettified_output is None:
        prettified_output = ""

    xml_parts.append('  <RawOutput>')
    xml_parts.append('    <![CDATA[')
    for line in str(prettified_output).split('\n'):
        xml_parts.append(f'    {line}')
    xml_parts.append('    ]]>')
    xml_parts.append('  </RawOutput>')

    xml_parts.append('</LightScanReport>')

    return '\n'.join(xml_parts)


if platform.system() == "Windows":
    try:
        print(f"\n[+] Running: {args.C}")
        print(f"[+] Saving to: {filename}\n")
        print("-" * 60)

        output_lines = []

        if args.S.lower() in ["txt", "light"]:
            result = subprocess.run(args.C, shell=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
            print(output)
            output_lines = output

        else:
            process = subprocess.Popen(args.C, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       bufsize=1)

            while True:
                stdout_line = process.stdout.readline()
                stderr_line = process.stderr.readline()

                if stdout_line:
                    print(stdout_line, end='')
                    output_lines.append(stdout_line)
                if stderr_line:
                    print(stderr_line, end='')
                    output_lines.append(stderr_line)

                if not stdout_line and not stderr_line and process.poll() is not None:
                    break

            output = ''.join(output_lines)

        print("-" * 60)

        if args.S.lower() in ["txt", "light"]:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\n[+] Scan saved to {filename}")

        elif args.S.lower() == "html":
            print(f"\n[+] Generating HTML report...")
            parsed_data = parse_scan_output(output)
            html_content = generate_html(parsed_data, output)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[+] HTML report saved to {filename}")

        elif args.S.lower() == "xml":
            print(f"\n[+] Generating XML report...")
            parsed_data = parse_scan_output(output)
            xml_content = generate_xml(parsed_data, output)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(xml_content)
            print(f"[+] XML report saved to {filename}")

        elif args.S.lower() == "csv":
            print(f"\n[+] Generating CSV report...")
            parsed_data = parse_scan_output(output)
            csv_content = generate_csv(parsed_data, output)
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                f.write(csv_content)
            print(f"[+] CSV report saved to {filename}")

        elif args.S.lower() == "json":
            print(f"\n[+] Generating JSON report...")
            parsed_data = parse_scan_output(output)
            json_content = generate_json(parsed_data, output)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(json_content)
            print(f"[+] JSON report saved to {filename}")

    except Exception as e:
        print(f"\n[-] Error: {e}")
else:
    print("[-] LightSave currently supports Windows only")