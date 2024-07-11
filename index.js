// import all the requirements
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token is required');

  const bearerToken = token.split(' ')[1]; // Extract the token part

  jwt.verify(bearerToken, process.env.SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).send('Invalid token');
    req.userId = decoded.id;
    next();
  });
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { name, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, password) VALUES ($1, $2) RETURNING *',
      [name, hashedPassword]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, {
      expiresIn: '1h',
    });
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { name, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE name = $1', [
      name,
    ]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, {
      expiresIn: '1h',
    });
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test endpoint to verify token
app.get('/protected', verifyToken, (req, res) => {
  res.status(200).json({ message: 'This is a protected route' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
