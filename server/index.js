const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const dotenv = require('dotenv');
const adminMiddleware = require('./middleware/adminMiddleware');

dotenv.config();

const app = express();
app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL connected...');
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.status(201).json({ message: 'User registered successfully!' });
    });
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (results.length === 0) return res.status(401).json({ message: 'User not found!' });
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'Invalid credentials!' });
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Middleware to verify JWT
const verifyJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(403);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// User profile endpoint
app.get('/api/user/profile', verifyJWT, (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results[0]);
    });
});

// Mod download endpoint
app.get('/api/mod/download/:modId', verifyJWT, (req, res) => {
    // Check subscription status
    db.query('SELECT subs_active FROM users WHERE id = ?', [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err });
        if (!results[0].subs_active) return res.status(403).json({ message: 'Subscription required!' });
        // Replace with actual mod download logic
        res.json({ message: 'Mod downloaded successfully!' });
    });
});

// Admin routes
app.use('/api/admin', adminMiddleware);

app.get('/api/admin/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results);
    });
});

app.get('/api/admin/subscriptions', (req, res) => {
    db.query('SELECT * FROM subscriptions', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results);
    });
});

app.get('/api/admin/logs', (req, res) => {
    db.query('SELECT * FROM logs', (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
