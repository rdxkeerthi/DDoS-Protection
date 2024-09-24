import os
import time
import socket
import threading
from collections import defaultdict

# CEP system configuration
CEP_SERVER_HOST = 'localhost'
CEP_SERVER_PORT = 5500

# DDoS protection configuration
THRESHOLD_CONCURRENT_CONNECTIONS = 100
THRESHOLD_REQUESTS_PER_SECOND = 50
BLOCK_IP_TIMEOUT = 300  # 5 minutes

# IP address blocking list
blocked_ips = set()

# Request counter
request_counter = defaultdict(int)

# Lock for request counter
request_counter_lock = threading.Lock()

# CEP system client
cep_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cep_client.connect((CEP_SERVER_HOST, CEP_SERVER_PORT))

def process_request(ip_address, request_time):
    # Increment request counter
    with request_counter_lock:
        request_counter[ip_address] += 1

    # Check for DDoS attack
    if request_counter[ip_address] > THRESHOLD_CONCURRENT_CONNECTIONS:
        # Block IP address
        blocked_ips.add(ip_address)
        print(f"Blocking IP address {ip_address} due to excessive connections")
        return False

    # Check for high request rate
    if request_counter[ip_address] > THRESHOLD_REQUESTS_PER_SECOND:
        # Block IP address
        blocked_ips.add(ip_address)
        print(f"Blocking IP address {ip_address} due to high request rate")
        return False

    # Send event to CEP system
    cep_client.send(f"Request from {ip_address} at {request_time}".encode())

    return True

def monitor_requests():
    while True:
        # Receive request from web server
        request = cep_client.recv(1024)
        if not request:
            break

        # Extract IP address and request time from request
        ip_address, request_time = request.decode().split(',')
        ip_address = ip_address.strip()
        request_time = float(request_time.strip())

        # Process request
        if not process_request(ip_address, request_time):
            continue

        # Update request counter
        with request_counter_lock:
            request_counter[ip_address] -= 1

        # Check for blocked IP addresses
        if ip_address in blocked_ips:
            print(f"Blocking request from {ip_address} due to previous block")
            continue

        # Allow request to proceed
        print(f"Allowing request from {ip_address}")

def main():
    # Start request monitoring thread
    threading.Thread(target=monitor_requests).start()

    # Periodically clean up blocked IP addresses
    while True:
        time.sleep(BLOCK_IP_TIMEOUT)
        blocked_ips.clear()

if __name__ == '__main__':
    main()