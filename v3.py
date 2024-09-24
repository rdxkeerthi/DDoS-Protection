from flask import Flask, request, jsonify
import redis
import time
import json

# Initialize Flask app
app = Flask(__name__)

# Initialize Redis for rate limiting
r = redis.StrictRedis(host='localhost', port=6379, db=0)

# Threshold for requests per second
REQUEST_THRESHOLD = 1000

# JSON log file
log_file = "mac_logs.json"

# Function to log IP addresses in a JSON file
def log_ip_address(ip_address):
    timestamp = time.time()

    # Log IP address and timestamp
    log_data = {
        "ip_address": ip_address,
        "timestamp": timestamp
    }

    # Append log to JSON file
    with open(log_file, "a") as f:
        f.write(json.dumps(log_data) + "\n")

# Function to block IP address using iptables
def block_ip_address(ip_address):
    print(f"Blocking IP address: {ip_address}")
    # Block the IP address using iptables
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    os.system(command)

# Middleware to check rate limiting
@app.before_request
def rate_limit_check():
    ip_address = request.remote_addr
    # Increment request count in Redis
    requests = r.incr(ip_address)

    if requests == 1:
        # Set expiry for the key after 1 second
        r.expire(ip_address, 1)

    if requests > REQUEST_THRESHOLD:
        # Log and block IP if it exceeds the threshold
        log_ip_address(ip_address)
        block_ip_address(ip_address)
        return jsonify({"error": "Too many requests, you have been blocked!"}), 429

# Main route
@app.route('/')
def index():
    return "Welcome to the website!"

# Start the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
