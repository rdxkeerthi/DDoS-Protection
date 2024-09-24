import scapy.all as scapy
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import subprocess
import schedule
import time
import logging
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set rate limit threshold (e.g. 100 packets per second)
rate_limit_threshold = 100

# Set specific IP address to monitor
monitored_ip = "192.168.74.129"

def run_script():
    try:
        # Sniff packets from specific IP address
        sniffer = scapy.sniff(iface="eth0", count=1000, filter=f"src {monitored_ip} or dst {monitored_ip}")
        df = pd.DataFrame(sniffer)

        # Calculate packet rates and statistics
        packet_rates = df.groupby("time").size().reset_index(name="count")
        packet_rates["rate"] = packet_rates["count"] / (df["time"].max() - df["time"].min())

        # Check if packet rate exceeds threshold
        if packet_rates["rate"].iloc[0] > rate_limit_threshold:
            logger.info(f"Packet rate from {monitored_ip} exceeds threshold: {packet_rates['rate'].iloc[0]}")
            # Block IP address if rate exceeds threshold
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", monitored_ip, "-j", "DROP"], check=True)
        else:
            logger.info(f"Packet rate from {monitored_ip} is within threshold: {packet_rates['rate'].iloc[0]}")

        # Plot packet rates over time
        plt.plot(df["time"], df["count"])
        plt.xlabel("Time")
        plt.ylabel("Packet Count")
        plt.title("Packet Rates Over Time for {}".format(monitored_ip))
        plt.show()

    except Exception as e:
        logger.error(f"Error running script: {e}")

schedule.every(1).minutes.do(run_script)  # Run script every 1 minute

try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    print("Script interrupted. Exiting...")
    sys.exit(0)