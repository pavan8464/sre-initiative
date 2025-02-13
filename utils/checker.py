import ssl
import socket
import warnings
import csv
import os
import time  # Added for timing measurements
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import concurrent.futures

##############################################
#   Basic Network and Certificate Functions  #
##############################################

def check_network_connection(hostname, port, timeout=3):
    try:
        socket.create_connection((hostname, port), timeout=timeout)
        return True
    except (socket.timeout, socket.error):
        return False

def is_self_signed(cert):
    if not cert:
        return False
    # A simple comparison: if issuer equals subject, assume self-signed.
    return cert.get("issuer") == cert.get("subject")

##############################################
#   Legacy TLS & Certificate Extraction      #
##############################################

def get_tls_and_certificate_details(hostname, port=443):
    """
    Legacy method using getpeercert() to extract TLS version and certificate details.
    (Not used in the optimized code.)
    """
    try:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        # Restrict to modern TLS versions.
        versions = {
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': ssl.TLSVersion.TLSv1_3
        }
        supported_versions = []
        for version_name, version in versions.items():
            try:
                context = ssl.create_default_context()
                context.minimum_version = version
                context.maximum_version = version
                with socket.create_connection((hostname, port), timeout=3) as conn:
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
            common_name = next(
                (value for field in cert.get("subject", []) for key, value in field if key == "commonName"),
                "Unknown"
            )
            return {
                'valid_from': cert.get('notBefore', 'Unknown'),
                'valid_to': cert.get('notAfter', 'Unknown'),
                'issuer': issuer_details,
                'subject': cert.get('subject', []),
                'common_name': common_name
            }

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
        if not is_self_signed(cert):
            return supported_versions, cert_details
        # Handle self-signed certificates.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)
        return supported_versions, cert_details
    except Exception as e:
        return None, None

def determine_cert_status(cert_valid_to):
    """
    Given a certificate expiry string (e.g. "Apr 14 08:36:03 2025 GMT"),
    determine the status and the number of days left.
    """
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

##############################################
#   New DER-based Certificate Extraction     #
##############################################

def get_der_certificate(hostname, port=443, timeout=3):
    """
    Attempts to get the DER-encoded certificate from the host.
    Uses the wrapped socket’s getpeercert(binary_form=True), or falls back to PEM conversion.
    """
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    return der_cert
    except Exception:
        pass
    # Fallback using get_server_certificate (returns PEM)
    try:
        pem_cert = ssl.get_server_certificate((hostname, port))
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        return der_cert
    except Exception:
        return None

def parse_der_cert(der_cert):
    """
    Parses a DER-encoded certificate using the cryptography library and
    returns a dictionary with certificate details.
    """
    cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
    
    # Build subject dictionary.
    subject = {}
    for attribute in cert_obj.subject:
        try:
            key = attribute.oid._name  # friendly name if available
        except AttributeError:
            key = attribute.oid.dotted_string
        subject[key] = attribute.value

    # Build issuer dictionary.
    issuer = {}
    for attribute in cert_obj.issuer:
        try:
            key = attribute.oid._name
        except AttributeError:
            key = attribute.oid.dotted_string
        issuer[key] = attribute.value

    # Get common name (if available)
    try:
        common_name = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        common_name = None

    # Use new UTC properties to avoid deprecation warnings.
    expiry_date = cert_obj.not_valid_after_utc
    expiry_str = expiry_date.strftime("%b %d %H:%M:%S %Y GMT")
    
    valid_from = cert_obj.not_valid_before_utc
    valid_from_str = valid_from.strftime("%b %d %H:%M:%S %Y GMT")
    
    return {
        "subject": subject,
        "issuer": issuer,
        "common_name": common_name,
        "valid_from": valid_from_str, 
        "valid_to": expiry_str,        # For export purposes.
        "expiry_date": expiry_date     # For internal calculation.
    }

def get_supported_tls_versions(hostname, port=443, timeout=3):
    """
    Attempts to connect to the host while forcing different TLS versions.
    Returns a list of TLS version strings that the host supports.
    """
    supported = []
    try:
        from ssl import TLSVersion
        # Limit to modern versions.
        tls_versions = [TLSVersion.TLSv1_2, TLSVersion.TLSv1_3]
        version_names = {
            TLSVersion.TLSv1_2: "TLSv1.2",
            TLSVersion.TLSv1_3: "TLSv1.3",
        }
        for ver in tls_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ver
                context.maximum_version = ver
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported.append(version_names[ver])
            except Exception:
                pass
    except ImportError:
        # Fallback if TLSVersion is not available.
        protocols = [
            (ssl.PROTOCOL_TLSv1_2, "TLSv1.2"),
        ]
        for proto, name in protocols:
            try:
                context = ssl.SSLContext(proto)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported.append(name)
            except Exception:
                pass
    return supported

##############################################
#   Main Certificate Check Function          #
##############################################

def check_host(hostname, port=443):
    """
    Checks a host's certificate details:
      - Verifies network connectivity.
      - Retrieves supported TLS versions.
      - Obtains and parses the DER-encoded certificate.
      - Calculates days left until expiry.
      - Determines if the certificate is self-signed.
      - Records the time taken for the check.
    """
    start_time = time.perf_counter()
    result = {
        'hostname': hostname,
        'port': port,
        'reachable': False,
        'tls_version': [],
        'certificate': {},
        'status': "No Certificate",
        'days_left': None,
        'common_name': None,
        'certificate_type': None,
        'time_taken': None  # New field to record check duration
    }
    try:
        # Check network connectivity.
        reachable = check_network_connection(hostname, port, timeout=3)
        result['reachable'] = reachable
        if not reachable:
            result['status'] = "Host Unreachable"
            return result

        # Get supported TLS versions.
        result['tls_version'] = get_supported_tls_versions(hostname, port, timeout=3)

        # Retrieve the DER-encoded certificate.
        der_cert = get_der_certificate(hostname, port, timeout=3)
        if der_cert:
            parsed_cert = parse_der_cert(der_cert)
        else:
            parsed_cert = {}

        if parsed_cert:
            subject = parsed_cert.get("subject", {})
            issuer = parsed_cert.get("issuer", {})
            result['common_name'] = parsed_cert.get("common_name", None)
            
            # Determine if the certificate is self-signed.
            if subject and issuer and subject == issuer:
                result['certificate_type'] = "Self Signed"
            else:
                result['certificate_type'] = "Not Self Signed"

            result['certificate'] = parsed_cert

            # Calculate certificate expiry details.
            expiry_date = parsed_cert.get("expiry_date")
            if expiry_date:
                now = datetime.now(timezone.utc)
                days_left = (expiry_date - now).days
                result['days_left'] = days_left
                result['status'] = "Valid" if days_left >= 0 else "Expired"
            else:
                result['status'] = "No Expiry Info"
        else:
            result['status'] = "No Certificate"
    except Exception as e:
        result['status'] = "Error: " + str(e)
        result['days_left'] = None
    end_time = time.perf_counter()
    elapsed = end_time - start_time
    result['time_taken'] = elapsed
    print(f"Host {hostname}:{port} checked in {elapsed:.2f} seconds")
    return result

##############################################
#   Bulk Processing Functions                #
##############################################

def process_bulk_hosts(file_path):
    overall_start = time.perf_counter()
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            tasks = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for idx, row in enumerate(csv_reader, start=1):
                    if not row:
                        continue
                    hostname_field = row.get('hostname')
                    if not hostname_field:
                        continue
                    # Support multiple hosts in one cell (comma-separated)
                    hostnames = [h.strip() for h in hostname_field.split(",") if h.strip()]
                    try:
                        port = int(row.get('port', 443))
                    except ValueError:
                        port = 443
                    for hostname in hostnames:
                        print(f"Processing row {idx}: hostname {hostname}, port {port}")
                        tasks.append(executor.submit(check_host, hostname, port))
                for future in concurrent.futures.as_completed(tasks):
                    result = future.result()
                    if result:
                        # Optionally add recipient information from the CSV row
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
        overall_end = time.perf_counter()
        total_time = overall_end - overall_start
        print(f"Processed bulk hosts in {total_time:.2f} seconds")
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

def check_bulk_hosts(file_path):
    return process_bulk_hosts(file_path)
