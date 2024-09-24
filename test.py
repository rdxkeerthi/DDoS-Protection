import os
import time
import socket
import threading
from collections import defaultdict, deque

# Firewall configuration
FIREWALL_HOST = 'localhost'
FIREWALL_PORT = 5500

# DDoS protection configuration
CONCURRENT_CONNECTIONS_THRESHOLD = 100
REQUESTS_PER_SECOND_THRESHOLD = 50
BLOCK_IP_TIMEOUT = 300  # 5 minutes

# IP address blocking list
blocked_ips = set()

# Request counter
request_counter = defaultdict(int)
request_counter_lock = threading.Lock()

# Request rate calculation data structure
request_rate_data = defaultdict(lambda: deque(maxlen=REQUESTS_PER_SECOND_THRESHOLD))

# Firewall rules
firewall_rules = {
    'allow': [],
    'deny': []
}

def add_firewall_rule(rule_type, ip_address):
    """
    Add a firewall rule.

    Args:
        rule_type (str): 'allow' or 'deny'
        ip_address (str): The IP address to add to the rule
    """
    if rule_type == 'allow':
        firewall_rules['allow'].append(ip_address)
    elif rule_type == 'deny':
        firewall_rules['deny'].append(ip_address)

def remove_firewall_rule(rule_type, ip_address):
    """
    Remove a firewall rule.

    Args:
        rule_type (str): 'allow' or 'deny'
        ip_address (str): The IP address to remove from the rule
    """
    if rule_type == 'allow':
        firewall_rules['allow'].remove(ip_address)
    elif rule_type == 'deny':
        firewall_rules['deny'].remove(ip_address)

def process_request(ip_address, request_time):
    """
    Process a request from an IP address.

    Args:
        ip_address (str): The IP address of the request
        request_time (float): The timestamp of the request

    Returns:
        bool: True if the request is allowed, False otherwise
    """
    with request_counter_lock:
        request_counter[ip_address] += 1

    if request_counter[ip_address] > CONCURRENT_CONNECTIONS_THRESHOLD:
        blocked_ips.add(ip_address)
        print(f"Blocking IP address {ip_address} due to excessive connections")
        return False

    # Calculate request rate
    request_rate = calculate_request_rate(ip_address, request_time)
    if request_rate > REQUESTS_PER_SECOND_THRESHOLD:
        blocked_ips.add(ip_address)
        print(f"Blocking IP address {ip_address} due to high request rate")
        return False

    # Check firewall rules
    if ip_address in firewall_rules['deny']:
        print(f"Denying request from {ip_address} due to firewall rule")
        return False
    elif ip_address in firewall_rules['allow']:
        print(f"Allowing request from {ip_address} due to firewall rule")
        return True

    # Default behavior: allow request
    return True

def calculate_request_rate(ip_address, request_time):
    """
    Calculate the request rate for an IP address.

    Args:
        ip_address (str): The IP address of the request
        request_time (float): The timestamp of the request

    Returns:
        float: The request rate
    """
    # Get the request rate data for the IP address
    ip_data = request_rate_data[ip_address]

    # Add the current request to the window
    ip_data.append(request_time)

    # Calculate the request rate
    window_start = ip_data[0]
    window_end = ip_data[-1]
    window_size = window_end - window_start
    request_rate = len(ip_data) / window_size

    return request_rate

def monitor_requests():
    """
    Monitor incoming requests and apply DDoS protection rules.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((FIREWALL_HOST, FIREWALL_PORT))
    sock.listen(1)

    while True:
        conn, addr = sock.accept()
        ip_address = addr[0]
        request_time = time.time()

        if not process_request(ip_address, request_time):
            conn.close()
            continue

        # Allow request to pass through
        print(f"Allowing request from {ip_address}")
        conn.close()

def main():
    """
    Start the firewall.
    """
    threading.Thread(target=monitor_requests).start()

    while True:
        time.sleep(BLOCK_IP_TIMEOUT)
        blocked_ips.clear()

if __name__ == '__main__':
    main()

# Example usage:
# python firewall.py