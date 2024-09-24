import time
import json
from scapy.all import sniff
import os

# Initialize variables
mac_requests = {}
blocked_macs = set()
log_file = "mac_logs.json"
threshold = 1000  # requests per second limit

# Function to log MAC address activity to JSON file
def log_mac_address(mac_address):
    timestamp = time.time()

    # Log request count
    if mac_address in mac_requests:
        mac_requests[mac_address]['count'] += 1
    else:
        mac_requests[mac_address] = {'count': 1, 'last_seen': timestamp}

    # Write to JSON log
    log_data = {
        "mac_address": mac_address,
        "timestamp": timestamp,
        "count": mac_requests[mac_address]['count']
    }

    with open(log_file, "a") as f:
        f.write(json.dumps(log_data) + "\n")

# Function to reset MAC request counts every second
def reset_mac_requests():
    while True:
        time.sleep(1)
        for mac in mac_requests:
            mac_requests[mac]['count'] = 0

# Function to block a MAC address using iptables
def block_mac_address(mac_address):
    if mac_address not in blocked_macs:
        os.system(f"sudo iptables -A INPUT -m mac --mac-source {mac_address} -j DROP")
        blocked_macs.add(mac_address)
        print(f"Blocked MAC address: {mac_address}")

# Function to handle each incoming packet
def process_packet(packet):
    if packet.haslayer("Ether"):
        mac_address = packet["Ether"].src
        log_mac_address(mac_address)

        # Check if request count exceeds the threshold
        if mac_requests[mac_address]['count'] > threshold:
            block_mac_address(mac_address)

# Main function to capture network traffic
def capture_traffic():
    print("Starting packet sniffing...")
    sniff(prn=process_packet)

if __name__ == "__main__":
    # Start the reset thread to clear MAC request counts every second
    import threading
    reset_thread = threading.Thread(target=reset_mac_requests)
    reset_thread.daemon = True
    reset_thread.start()

    # Start capturing traffic
    capture_traffic()
