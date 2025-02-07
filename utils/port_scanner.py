import sys
import time
import socket
from global_data import multi_scan_result, bulk_port_scan_result
from utils.checker import check_host

def scan_ports(host, start_port, end_port, socketio, only_ports=False):
    print(f"[DEBUG] scan_ports() called with host: {host}, start_port: {start_port}, end_port: {end_port}")
    
    open_ports = []
    total_ports = end_port - start_port + 1
    estimated_total_time = total_ports * 0.5  # assuming 0.5 sec per port scan
    socketio.emit('update', {'message': f"Estimated total time: {estimated_total_time:.2f} sec", 'progress': 0})
    
    for index, port in enumerate(range(start_port, end_port + 1), start=1):
        message = f"Checking port {port} ({index}/{total_ports}) on host {host} | ETA: {max((total_ports-index)*0.5, 0):.2f} sec"
        sys.stdout.write("\r" + message)
        sys.stdout.flush()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
        socketio.emit('update', {'message': message, 'progress': (index/total_ports)*100})
        socketio.sleep(0.5)
    print()
    
    if not only_ports:
        certificates = {}
        for port in open_ports:
            try:
                cert_result = check_host(host, port)
                certificates[port] = cert_result
            except Exception as e:
                certificates[port] = {"error": str(e)}
    else:
        certificates = {}
    
    result_data = {
        "hostname": host,
        "checked_ports_range": f"{start_port}-{end_port}",
        "open_ports": open_ports,
        "reachable": "Yes",
        "certificates": certificates,
        "scan_type": "port" if only_ports else "certificate"
    }
    
    multi_scan_result.clear()
    multi_scan_result.update(result_data)
    socketio.emit('completion', {
        'message': "Scanning complete!",
        'hostname': host,
        'startPort': start_port,
        'endPort': end_port,
        'open_ports': open_ports
    })
    
    return result_data

def scan_bulk_ports(file_path, socketio):
    """
    Reads a CSV file containing rows with hostname, start_port, and end_port.
    Scans each host and emits progress updates (including ETA) via Socket.IO.
    Results are stored in the global variable bulk_port_scan_result.
    """
    results = []
    try:
        import csv
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            rows = list(csv_reader)
            total_hosts = len(rows)
            socketio.emit('update', {
                'message': f"Starting bulk port scan for {total_hosts} host(s)...",
                'progress': 0
            }, namespace='/bulk')
            for idx, row in enumerate(rows, start=1):
                hostname = row.get('hostname')
                try:
                    start_port = int(row.get('start_port', 0))
                    end_port = int(row.get('end_port', 0))
                except ValueError:
                    continue
                if not hostname or start_port == 0 or end_port == 0:
                    continue

                open_ports = []
                total_ports = end_port - start_port + 1
                # Scan each port for this host
                for i, port in enumerate(range(start_port, end_port + 1), start=1):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        res = s.connect_ex((hostname, port))
                        if res == 0:
                            open_ports.append(port)
                    # Calculate progress for this host and overall progress
                    progress_for_host = (i / total_ports) * 100
                    overall_progress = ((idx - 1) / total_hosts) * 100 + (progress_for_host / total_hosts)
                    socketio.emit('update', {
                        'message': f"Scanning {hostname} ({idx}/{total_hosts}) port {port} ({i}/{total_ports})",
                        'progress': overall_progress
                    }, namespace='/bulk')
                    socketio.sleep(0.1)
                results.append({
                    "hostname": hostname,
                    "start_port": start_port,
                    "end_port": end_port,
                    "open_ports": open_ports
                })
            # Store the results in the global variable so they can be later displayed
            bulk_port_scan_result.clear()
            bulk_port_scan_result.extend(results)
            socketio.emit('completion', {
                'message': "Bulk scanning complete!",
                'results': results
            }, namespace='/bulk')
    except Exception as e:
        socketio.emit('update', {
            'message': f"Error during bulk scan: {str(e)}",
            'progress': 100
        }, namespace='/bulk')
    return results
