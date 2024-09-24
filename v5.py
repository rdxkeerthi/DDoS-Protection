from flask import Flask, request, jsonify, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import json
from datetime import datetime

app = Flask(__name__)

# Initialize Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["2 per minute"]  # Example rate limit
)

# Middleware to log IP addresses
@app.before_request
def log_ip():
    ip = request.remote_addr
    print(f"User IP: {ip}")

    # Log user data to JSON
    user_data = {
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat()
    }
    log_user_data(user_data)

def log_user_data(data):
    try:
        with open('user-data.json', 'a') as f:
            json.dump(data, f)
            f.write('\n')  # Write each record on a new line
    except Exception as e:
        print(f"Error logging user data: {e}")

# Rate limiting handler
@app.errorhandler(429)
def ratelimit_error(e):
    ip = request.remote_addr
    print(f"IP {ip} exceeded the rate limit.")
    return jsonify({
        "error": "rate_limit_exceeded",
        "message": "Too many requests. Try again later.",
        "ip": ip
    }), 429

# Route to verify CAPTCHA or human check
@app.route('/human-verification', methods=['GET'])
def human_verification():
    return jsonify({
        "message": "Human verification required. Please complete CAPTCHA."
    })

# Route to handle CAPTCHA verification
@app.route('/verify', methods=['POST'])
def verify():
    # Here you would verify the CAPTCHA response (if implemented)
    return jsonify({"message": "Verification successful!"})

# Main route for IP logging and general information
@app.route('/')
def home():
    ip = request.remote_addr
    return jsonify({
        "message": "Welcome to the API!",
        "ip": ip,
        "note": "Your IP is being monitored for security purposes."
    })

# API endpoint to return user information
@app.route('/api/user-data', methods=['GET'])
def get_user_data():
    try:
        with open('user-data.json', 'r') as f:
            user_data = [json.loads(line) for line in f]
        return jsonify(user_data)
    except FileNotFoundError:
        return jsonify({"message": "No user data found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=3000)
