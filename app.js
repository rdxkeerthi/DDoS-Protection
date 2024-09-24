const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');
const redis = require('redis'); // Redis client for rate limiting
const { RateLimitRedisStore } = require('rate-limit-redis');

const app = express();
const port = 3000;

// Use Helmet to secure HTTP headers
app.use(helmet());

// Connect to Redis
const redisClient = redis.createClient({
  host: '127.0.0.1', // Redis server address
  port: 6379, // Redis server port
});

// Function to log user data into a JSON file
const logUserData = (ip, filePath) => {
  const userData = {
    ip: ip,
    timestamp: new Date().toISOString(),
  };

  // Read existing JSON data from the file
  fs.readFile(filePath, (err, data) => {
    if (err && err.code === 'ENOENT') {
      fs.writeFileSync(filePath, JSON.stringify([userData], null, 2));
    } else {
      const existingData = JSON.parse(data || '[]');
      existingData.push(userData);
      fs.writeFileSync(filePath, JSON.stringify(existingData, null, 2));
    }
  });
};

// Middleware to log IP addresses and store in JSON
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`User IP: ${ip}`);

  const filePath = path.join(__dirname, 'user-data.json');
  logUserData(ip, filePath);

  next();
});

// Rate limiting with Redis as the store
const requestLimiter = rateLimit({
  store: new RateLimitRedisStore({
    sendCommand: (...args) => redisClient.call(...args), // Redis client
  }),
  windowMs: 60 * 1000, // 1 minute window
  max: 1000, // Limit each IP to 1000 requests per minute
  message: 'Too many requests from this IP, please verify you are human.',
  handler: (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`IP ${ip} exceeded the rate limit. Moving to human verification.`);

    const filePath = path.join(__dirname, 'blocked-ips.json');
    logUserData(ip, filePath);

    res.redirect('/human-verification');
  },
});

// Apply the rate limiter globally
app.use(requestLimiter);

// Human verification page (e.g., CAPTCHA)
app.get('/human-verification', (req, res) => {
  res.send(`
    <h1>Human Verification Required</h1>
    <p>To continue, please complete the CAPTCHA below.</p>
    <!-- Embed CAPTCHA (e.g., Google reCAPTCHA) -->
    <form action="/verify" method="POST">
      <div class="g-recaptcha" data-sitekey="your-site-key"></div>
      <br />
      <input type="submit" value="Verify">
    </form>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  `);
});

// Route to handle CAPTCHA verification
app.post('/verify', (req, res) => {
  res.send('Verification successful! You are now allowed to access the site.');
});

// Main route (test route)
app.get('/', (req, res) => {
  res.send('Welcome to the site! Your IP is being monitored for security purposes.');
});

// Start the server
app.listen(port, () => {
  console.log(`Web firewall running at http://localhost:${port}`);
});
