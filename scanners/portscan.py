import subprocess
import re

def scan_ports(hosts):
    """
    Scan ports 1-10000 on each host in the list using nmap.
    Returns a dict mapping host -> list of open ports or error info.
    """
    results = {}
    for host in hosts:
        try:
            # Use nmap grepable output
            cmd = ['nmap', '-p1-10000', '-T4', '-Pn', host, '-oG', '-']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = proc.stdout
            ports = []
            for line in output.splitlines():
                if line.startswith('Host:'):
                    m = re.search(r'Ports: (.*)$', line)
                    if m:
                        port_list = m.group(1)
                        for part in port_list.split(','):
                            fields = part.split('/')
                            if len(fields) > 1 and fields[1] == 'open':
                                try:
                                    ports.append(int(fields[0]))
                                except ValueError:
                                    pass
            results[host] = ports
        except Exception as e:
            results[host] = {'error': str(e)}
    return results