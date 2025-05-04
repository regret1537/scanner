import subprocess
import re

def scan_ports(hosts, port_range=None):
    """
    Scan ports in the given range on each host using nmap.
    port_range: [start, end], defaults to 1-10000.
    Returns a dict mapping host -> list of open ports or error info.
    """
    results = {}
    # determine port range
    try:
        if isinstance(port_range, (list, tuple)) and len(port_range) == 2:
            p_start, p_end = int(port_range[0]), int(port_range[1])
        else:
            p_start, p_end = 1, 10000
    except Exception:
        p_start, p_end = 1, 10000
    for host in hosts:
        try:
            # Use nmap grepable output
            port_spec = f"{p_start}-{p_end}"
            cmd = ['nmap', f'-p{port_spec}', '-T4', '-Pn', host, '-oG', '-']
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