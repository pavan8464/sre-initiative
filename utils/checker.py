import ssl
import socket
import warnings
import csv
import os
from datetime import datetime

def check_network_connection(hostname, port):
    try:
        socket.create_connection((hostname, port), timeout=5)
        return True
    except (socket.timeout, socket.error):
        return False

def is_self_signed(cert):
    if not cert:
        return False
    # A simple comparison: if issuer equals subject, assume self-signed.
    return cert.get("issuer") == cert.get("subject")

def get_tls_and_certificate_details(hostname, port=443):
    try:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        versions = {
            'TLSv1': ssl.TLSVersion.TLSv1,
            'TLSv1.1': ssl.TLSVersion.TLSv1_1,
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': ssl.TLSVersion.TLSv1_3
        }
        supported_versions = []
        for version_name, version in versions.items():
            try:
                context = ssl.create_default_context()
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((hostname, port), timeout=5) as conn:
                    with context.wrap_socket(conn, server_hostname=hostname) as sock:
                        cert = sock.getpeercert()
                        if cert and not is_self_signed(cert):
                            supported_versions.append(version_name)
            except (ssl.SSLError, socket.timeout):
                continue

        def extract_cert_details(cert):
            issuer_details = "\n".join(
                f"- {name}: {value}" for item in cert.get('issuer', []) for name, value in item
            )
            common_name = next((value for field in cert.get("subject", []) for key, value in field if key == "commonName"), "Unknown")
            return {
                'valid_from': cert.get('notBefore', 'Unknown'),
                'valid_to': cert.get('notAfter', 'Unknown'),
                'issuer': issuer_details,
                'subject': cert.get('subject', []),
                'common_name': common_name
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
        if not is_self_signed(cert):
            return supported_versions, cert_details
        # Handle self-signed certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
        return supported_versions, cert_details
    except Exception as e:
        return None, None

def determine_cert_status(cert_valid_to):
    if not cert_valid_to:
        return "Invalid", None
    try:
        expiry_date = datetime.strptime(cert_valid_to, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.now()).days
        if days_left < 0:
            return "Expired", days_left
        elif days_left <= 30:
            return f"Expiring Soon ({days_left} days left)", days_left
        return f"Valid ({days_left} days left)", days_left
    except Exception as e:
        print(f"Error determining certificate status: {e}")
        return "Invalid", None

def check_host(hostname, port=443):
    result = {
        'hostname': hostname,
        'port': port,
        'reachable': False,
        'tls_version': None,
        'certificate': {},
        'status': "No Certificate",
        'days_left': None,
        'common_name': None
    }
    try:
        reachable = check_network_connection(hostname, port)
        result['reachable'] = reachable
        if not reachable:
            result['status'] = "Host Unreachable"
            return result
        tls_version, cert_details = get_tls_and_certificate_details(hostname, port)
        result['tls_version'] = tls_version
        result['certificate'] = cert_details or {}
        if cert_details:
            result['common_name'] = cert_details.get("common_name")
        if not cert_details:
            result['status'] = "No Certificate"
        else:
            if cert_details.get('valid_to'):
                status, days_left = determine_cert_status(cert_details.get('valid_to'))
                result['status'] = status
                result['days_left'] = days_left
            else:
                result['status'] = "No Certificate"
                result['days_left'] = None
    except Exception as e:
        result['status'] = "Error"
        result['days_left'] = None
    return result

def process_bulk_hosts(file_path):
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx, row in enumerate(csv_reader, start=1):
                if not row:
                    continue
                hostname = row.get('hostname')
                if not hostname:
                    continue
                try:
                    port = int(row.get('port', 443))
                except ValueError:
                    port = 443
                print(f"Processing row {idx}: hostname {hostname}, port {port}")
                result = check_host(hostname, port)
                if result:
                    result['recipients'] = row.get('recipients')
                    cert = result.get('certificate')
                    if cert and cert != "N/A":
                        if is_self_signed(cert):
                            result['certificate_type'] = "Self Signed"
                        else:
                            result['certificate_type'] = "Not Self Signed"
                    else:
                        result['certificate_type'] = "N/A"
                    results.append(result)
    except FileNotFoundError:
        print(f"Error: File not found at path {file_path}")
    except Exception as e:
        print(f"Error processing bulk hosts: {e}")
    return results

def check_open_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

def process_bulk_ports(file_path):
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx, row in enumerate(csv_reader, start=1):
                hostname = row.get('hostname')
                try:
                    start_port = int(row.get('start_port', 0))
                    end_port = int(row.get('end_port', 0))
                except ValueError:
                    continue
                if not hostname or start_port == 0 or end_port == 0:
                    continue
                open_ports = check_open_ports(hostname, start_port, end_port)
                results.append({
                    "hostname": hostname,
                    "start_port": start_port,
                    "end_port": end_port,
                    "open_ports": open_ports
                })
    except Exception as e:
        print(f"Error processing bulk ports: {e}")
    return results

# Add the missing function so it can be imported from app.py
def check_bulk_hosts(file_path):
    return process_bulk_hosts(file_path)
