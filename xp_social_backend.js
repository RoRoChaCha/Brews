// server.js - XP Social Backend API
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Database setup
const dbPath = path.join(__dirname, 'xpsocial.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        avatar TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Likes table
    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, message_id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (message_id) REFERENCES messages (id)
    )`);

    // Insert demo data
    const demoUsers = [
        { username: 'demo', password: 'demo', avatar: '😊' },
        { username: 'alice', password: 'password', avatar: '😄' },
        { username: 'bob', password: 'password', avatar: '😎' }
    ];

    demoUsers.forEach(user => {
        const hashedPassword = bcrypt.hashSync(user.password, 10);
        db.run(`INSERT OR IGNORE INTO users (username, password_hash, avatar) VALUES (?, ?, ?)`,
            [user.username, hashedPassword, user.avatar]);
    });

    // Insert demo messages
    setTimeout(() => {
        db.get("SELECT id FROM users WHERE username = 'alice'", (err, alice) => {
            if (alice) {
                db.run(`INSERT OR IGNORE INTO messages (user_id, content) VALUES (?, ?)`,
                    [alice.id, 'Hello everyone! Welcome to XP Social! 🎉']);
            }
        });

        db.get("SELECT id FROM users WHERE username = 'bob'", (err, bob) => {
            if (bob) {
                db.run(`INSERT OR IGNORE INTO messages (user_id, content) VALUES (?, ?)`,
                    [bob.id, 'This retro interface brings back so many memories! Love the Windows XP theme.']);
            }
        });
    }, 100);
});

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many authentication attempts, please try again later.'
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Validation middleware
const validateRegistration = [
    body('username')
        .isLength({ min: 3, max: 20 })
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username must be 3-20 characters and contain only letters, numbers, and underscores'),
    body('password')
        .isLength({ min: 4 })
        .withMessage('Password must be at least 4 characters long'),
    body('avatar')
        .matches(/^[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}]$/u)
        .withMessage('Avatar must be a valid emoji')
];

const validateLogin = [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
];

const validateMessage = [
    body('content')
        .isLength({ min: 1, max: 500 })
        .withMessage('Message must be between 1 and 500 characters')
];

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// User registration
app.post('/api/auth/register', authLimiter, validateRegistration, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, password, avatar } = req.body;

    // Check if user already exists
    db.get("SELECT id FROM users WHERE username = ?", [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (row) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password and create user
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        db.run("INSERT INTO users (username, password_hash, avatar) VALUES (?, ?, ?)",
            [username, hashedPassword, avatar], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create user' });
            }

            const token = jwt.sign(
                { userId: this.lastID, username: username },
                JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.status(201).json({
                message: 'User created successfully',
                token: token,
                user: {
                    id: this.lastID,
                    username: username,
                    avatar: avatar
                }
            });
        });
    });
});

// User login
app.post('/api/auth/login', authLimiter, validateLogin, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user || !bcrypt.compareSync(password, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                username: user.username,
                avatar: user.avatar
            }
        });
    });
});

// Get user profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db.get("SELECT id, username, avatar, created_at FROM users WHERE id = ?", 
        [req.user.userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user });
    });
});

// Get all messages
app.get('/api/messages', authenticateToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const query = `
        SELECT 
            m.id,
            m.content,
            m.created_at,
            u.username,
            u.avatar,
            COUNT(l.id) as like_count,
            CASE WHEN ul.user_id IS NOT NULL THEN 1 ELSE 0 END as user_liked
        FROM messages m
        JOIN users u ON m.user_id = u.id
        LEFT JOIN likes l ON m.id = l.message_id
        LEFT JOIN likes ul ON m.id = ul.message_id AND ul.user_id = ?
        GROUP BY m.id, u.username, u.avatar, ul.user_id
        ORDER BY m.created_at DESC
        LIMIT ? OFFSET ?
    `;

    db.all(query, [req.user.userId, limit, offset], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        const formattedMessages = messages.map(msg => ({
            id: msg.id,
            content: msg.content,
            timestamp: new Date(msg.created_at).toLocaleString(),
            username: msg.username,
            avatar: msg.avatar,
            likes: msg.like_count,
            userLiked: msg.user_liked === 1
        }));

        res.json({ messages: formattedMessages });
    });
});

// Create new message
app.post('/api/messages', authenticateToken, validateMessage, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { content } = req.body;

    db.run("INSERT INTO messages (user_id, content) VALUES (?, ?)",
        [req.user.userId, content], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to create message' });
        }

        // Get the created message with user info
        db.get(`
            SELECT 
                m.id,
                m.content,
                m.created_at,
                u.username,
                u.avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [this.lastID], (err, message) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.status(201).json({
                message: 'Message created successfully',
                data: {
                    id: message.id,
                    content: message.content,
                    timestamp: new Date(message.created_at).toLocaleString(),
                    username: message.username,
                    avatar: message.avatar,
                    likes: 0,
                    userLiked: false
                }
            });
        });
    });
});

// Like/Unlike message
app.post('/api/messages/:id/like', authenticateToken, (req, res) => {
    const messageId = parseInt(req.params.id);
    
    if (isNaN(messageId)) {
        return res.status(400).json({ error: 'Invalid message ID' });
    }

    // Check if message exists
    db.get("SELECT id FROM messages WHERE id = ?", [messageId], (err, message) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Check if user already liked this message
        db.get("SELECT id FROM likes WHERE user_id = ? AND message_id = ?",
            [req.user.userId, messageId], (err, existingLike) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (existingLike) {
                // Unlike - remove the like
                db.run("DELETE FROM likes WHERE user_id = ? AND message_id = ?",
                    [req.user.userId, messageId], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to unlike message' });
                    }
                    res.json({ message: 'Message unliked', liked: false });
                });
            } else {
                // Like - add the like
                db.run("INSERT INTO likes (user_id, message_id) VALUES (?, ?)",
                    [req.user.userId, messageId], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to like message' });
                    }
                    res.json({ message: 'Message liked', liked: true });
                });
            }
        });
    });
});

// Get message likes
app.get('/api/messages/:id/likes', authenticateToken, (req, res) => {
    const messageId = parseInt(req.params.id);
    
    if (isNaN(messageId)) {
        return res.status(400).json({ error: 'Invalid message ID' });
    }

    db.all(`
        SELECT u.username, u.avatar, l.created_at
        FROM likes l
        JOIN users u ON l.user_id = u.id
        WHERE l.message_id = ?
        ORDER BY l.created_at DESC
    `, [messageId], (err, likes) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        res.json({ likes });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});

app.listen(PORT, () => {
    console.log(`🚀 XP Social API server running on port ${PORT}`);
    console.log(`📊 Health check available at http://localhost:${PORT}/api/health`);
});

module.exports = app;