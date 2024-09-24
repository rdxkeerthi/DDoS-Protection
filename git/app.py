from flask import Flask, request, jsonify, redirect, render_template, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import json
from datetime import datetime

app = Flask(__name__)

# Initialize Redis
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

# Initialize Flask-Limiter for rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5 per minute"]  # You can modify limits as needed
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

# Rate limiting handler (returns a message when rate limit is exceeded)
@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('error.html', message="You have exceeded the rate limit. Please try again later."), 429

# Serve HTML for home page
@app.route('/')
def home():
    return render_template('index.html')

# API route for user data
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

# Human verification route (HTML form to simulate CAPTCHA)
@app.route('/human-verification', methods=['GET'])
def human_verification():
    return render_template('captcha.html')

# Route to handle CAPTCHA verification
@app.route('/verify', methods=['POST'])
def verify():
    # You would normally verify a CAPTCHA response here
    return render_template('verification_success.html')

if __name__ == '__main__':
    app.run(port=3000)
