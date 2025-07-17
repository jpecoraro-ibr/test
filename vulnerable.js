// Vulnerable JavaScript file for CodeQL testing
// This file contains intentional security vulnerabilities for educational purposes

const express = require('express');
const app = express();
const mysql = require('mysql');

// 1. SQL Injection vulnerability
function getUserData(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'user',
        password: 'password',
        database: 'testdb'
    });
    
    // Vulnerable: Direct string concatenation allows SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
        if (error) throw error;
        console.log(results);
    });
}

// 2. Cross-Site Scripting (XSS) vulnerability
app.get('/user/:name', (req, res) => {
    const userName = req.params.name;
    // Vulnerable: Direct output without escaping
    res.send(`<h1>Hello ${userName}!</h1>`);
});

// 3. Path Traversal vulnerability
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    // Vulnerable: No validation of filename
    res.sendFile(`/uploads/${filename}`);
});

// 4. Command Injection vulnerability
const { exec } = require('child_process');

app.post('/ping', (req, res) => {
    const host = req.body.host;
    // Vulnerable: Direct execution of user input
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send('Error executing ping');
            return;
        }
        res.send(stdout);
    });
});

// 5. Hard-coded credentials
const API_KEY = "sk-1234567890abcdef";
const DATABASE_PASSWORD = "admin123";

// 6. Weak cryptographic practices
const crypto = require('crypto');

function weakHash(password) {
    // Vulnerable: MD5 is cryptographically weak
    return crypto.createHash('md5').update(password).digest('hex');
}

// 7. Insecure random number generation
function generateToken() {
    // Vulnerable: Math.random() is not cryptographically secure
    return Math.random().toString(36).substr(2, 10);
}

// 8. Prototype pollution vulnerability
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: No protection against __proto__ manipulation
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 9. Regex Denial of Service (ReDoS)
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking possible
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    return emailRegex.test(email);
}

// 10. Insecure cookie settings
app.use(session({
    secret: 'weak-secret',
    cookie: {
        secure: false,    // Should be true in production
        httpOnly: false,  // Should be true
        maxAge: 86400000  // 24 hours
    }
}));

// 11. Information disclosure
app.get('/debug/:id', (req, res) => {
    try {
        const user = getUser(req.params.id);
        res.json(user);
    } catch (error) {
        // Vulnerable: Exposing internal error details
        res.status(500).json({
            error: error.message,
            stack: error.stack,
            code: error.code
        });
    }
});

// 12. Timing attack vulnerability
function authenticateUser(username, password) {
    const users = getUsers();
    for (let user of users) {
        // Vulnerable: Early return creates timing difference
        if (user.username !== username) {
            continue;
        }
        if (user.password === password) {
            return true;
        }
    }
    return false;
}

// 13. Unsafe deserialization
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    // Vulnerable: eval() can execute arbitrary code
    const result = eval(`(${data})`);
    res.json(result);
});

// 14. Missing input validation
app.post('/transfer', (req, res) => {
    const amount = req.body.amount;
    const toAccount = req.body.toAccount;
    
    // Vulnerable: No validation of amount or account
    transferMoney(amount, toAccount);
    res.send('Transfer completed');
});

// 15. Insufficient logging
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
        // Missing: Should log successful login
        res.json({ success: true });
    } else {
        // Missing: Should log failed login attempts
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.listen(3000, () => {
    console.log('Vulnerable app running on port 3000');
});

module.exports = app;