/**
 * InfoSec Project Backend
 * Requirements Implemented:
 * 1. User Authentication (Bcrypt hashing, JWT)
 * 2. Logging & Security Auditing (MongoDB storage of security events)
 * 3. Key Public Storage (Storing the public half of the asymmetric pair)
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Using bcrypt for secure password hashing
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 5000;
const JWT_SECRET = "super_secret_project_key_change_this_in_prod"; // In production, use ENV var

// Middleware
app.use(cors());
app.use(express.json());

// --- MONGODB CONNECTION ---
// Replace with your local or Atlas connection string
mongoose.connect('mongodb://127.0.0.1:27017/infosec_project', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

// --- SCHEMAS ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true }, // Store HASH, not plaintext
    publicKey: { type: Object, required: true }, // JWK Format
    createdAt: { type: Date, default: Date.now }
});

// Security Audit Log Schema
const logSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    type: { type: String, required: true }, // e.g., 'AUTH_SUCCESS', 'AUTH_FAIL', 'KEY_GEN', 'REPLAY_ATTACK'
    username: { type: String }, // Optional, if user is known
    ipAddress: { type: String },
    details: { type: String },
    severity: { type: String, enum: ['info', 'warning', 'critical'], default: 'info' }
});

const User = mongoose.model('User', userSchema);
const AuditLog = mongoose.model('AuditLog', logSchema);

// --- HELPER: LOGGING ---
const createLog = async (req, type, details, username = null, severity = 'info') => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        await AuditLog.create({
            type,
            details,
            username,
            ipAddress: ip,
            severity
        });
        console.log(`[AUDIT] ${type}: ${details}`);
    } catch (e) {
        console.error("Logging failed:", e);
    }
};

// --- ROUTES ---

// 1. REGISTER
app.post('/api/register', async (req, res) => {
    const { username, password, publicKey } = req.body;

    // Validate all required fields are present and not empty
    if (!username || typeof username !== 'string' || !username.trim()) {
        return res.status(400).json({ message: "Username is required" });
    }
    if (!password || typeof password !== 'string' || !password.trim()) {
        return res.status(400).json({ message: "Password is required" });
    }
    if (!publicKey || typeof publicKey !== 'object' || !publicKey.kty) {
        return res.status(400).json({ message: "Public key is required" });
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
app.post('/api/login', async (req, res) => {
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
app.post('/api/log', async (req, res) => {
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
app.get('/api/logs', async (req, res) => {
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
app.get('/api/users', async (req, res) => {
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
app.get('/api/users/:username/public-key', async (req, res) => {
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

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));