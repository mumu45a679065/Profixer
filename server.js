const express = require('express');
const app = express();
const port = 3000;
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET_KEY = 'your_secret_key'; // In a real app, use environment variables

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Welcome to the Login System');
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Registration Endpoint
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;

    db.run(query, [username, email, hashedPassword], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          if (err.message.includes('username')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          if (err.message.includes('email')) {
            return res.status(400).json({ error: 'Email already exists' });
          }
        }
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ id: this.lastID, username, email });
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Forgot Password Endpoint
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const query = `SELECT * FROM users WHERE email = ?`;
  db.get(query, [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      // For security, don't reveal that the user does not exist
      return res.json({ message: 'If that email is in our database, we have sent a reset token.' });
    }

    // Generate a reset token
    const token = crypto.randomBytes(20).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour

    const updateQuery = `UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?`;
    db.run(updateQuery, [token, expires, user.id], (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      // In a real application, send this token via email
      // Here we return it for testing purposes
      res.json({ message: 'Reset token generated', token });
    });
  });
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  const query = `SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?`;
  db.get(query, [token, Date.now()], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(400).json({ error: 'Password reset token is invalid or has expired' });
    }

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const updateQuery = `UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?`;

      db.run(updateQuery, [hashedPassword, user.id], (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Password has been reset' });
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

// Login Endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Protected Route
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile', user: req.user });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
