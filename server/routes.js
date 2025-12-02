/**
 * InfoSec Project Routes
 * All API endpoints for authentication, logging, and user management
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = express.Router();

// JWT Secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_project_key_change_this_in_prod";

// Models will be injected via initialization function
let User, AuditLog, createLog;

// Initialize function to set dependencies
const initialize = (userModel, auditLogModel, createLogFn) => {
    User = userModel;
    AuditLog = auditLogModel;
    createLog = createLogFn;
};

// --- ROUTES ---

// 1. REGISTER
router.post('/register', async (req, res) => {
    const { username, password, publicKey } = req.body;

    if (!username || !password || !publicKey) {
        return res.status(400).json({ message: "Missing fields" });
    }

    try {
        // Check existing
        const existing = await User.findOne({ username });
        if (existing) {
            await createLog(req, 'AUTH_REGISTER_FAIL', `Attempt to register existing user: ${username}`, null, 'warning');
            return res.status(400).json({ message: "Username exists" });
        }

        // Hash Password (Bcrypt)
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Create User
        const newUser = new User({
            username,
            passwordHash,
            publicKey
        });
        await newUser.save();

        await createLog(req, 'AUTH_REGISTER_SUCCESS', `User registered and Public Key stored`, username, 'info');

        res.status(201).json({ message: "User registered successfully" });

    } catch (err) {
        await createLog(req, 'SYSTEM_ERROR', `Registration error: ${err.message}`, null, 'critical');
        res.status(500).json({ message: "Server error" });
    }
});

// 2. LOGIN
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            await createLog(req, 'AUTH_FAIL', `Login failed (User not found): ${username}`, null, 'warning');
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Verify Password
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) {
            await createLog(req, 'AUTH_FAIL', `Login failed (Invalid password): ${username}`, username, 'warning');
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Generate Token
        const token = jwt.sign({ userId: user._id, username }, JWT_SECRET, { expiresIn: '1h' });

        await createLog(req, 'AUTH_SUCCESS', `User logged in successfully`, username, 'info');
        res.json({ token, username });

    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// 3. LOG INGESTION (For Client-Side Security Events)
// Clients hit this endpoint to report failed decryptions, replay attacks, etc.
router.post('/log', async (req, res) => {
    // Verify JWT if present (optional but recommended)
    const authHeader = req.headers['authorization'];
    let username = 'anonymous';

    if (authHeader) {
        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            username = decoded.username;
        } catch (e) {
            // Invalid token
        }
    }

    const { type, details, severity } = req.body;
    await createLog(req, type, details, username, severity || 'info');
    res.sendStatus(200);
});

// 4. FETCH LOGS (For Dashboard Visualization)
router.get('/logs', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET); // Verify token

        // Return last 50 logs desc
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(50);
        res.json(logs);
    } catch (e) {
        res.sendStatus(403);
    }
});

// 5. GET ALL REGISTERED USERS (For User Directory)
router.get('/users', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        // Fetch all users except the requesting user
        const users = await User.find(
            { username: { $ne: decoded.username } },
            { username: 1, createdAt: 1, _id: 1 }
        ).sort({ username: 1 });

        await createLog(req, 'USER_DIRECTORY_ACCESS', `User ${decoded.username} accessed user directory`, decoded.username, 'info');
        
        res.json(users);
    } catch (e) {
        res.sendStatus(403);
    }
});

// 6. GET SPECIFIC USER'S PUBLIC KEY (For Key Exchange)
router.get('/users/:username/public-key', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const targetUsername = req.params.username;

        const targetUser = await User.findOne({ username: targetUsername }, { publicKey: 1, username: 1 });
        
        if (!targetUser) {
            await createLog(req, 'KEY_FETCH_FAIL', `User ${decoded.username} requested key for non-existent user: ${targetUsername}`, decoded.username, 'warning');
            return res.status(404).json({ message: "User not found" });
        }

        await createLog(req, 'KEY_FETCH_SUCCESS', `User ${decoded.username} fetched public key for ${targetUsername}`, decoded.username, 'info');
        
        res.json({ username: targetUser.username, publicKey: targetUser.publicKey });
    } catch (e) {
        res.sendStatus(403);
    }
});

module.exports = { router, initialize };
