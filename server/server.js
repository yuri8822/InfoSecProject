/**
 * InfoSec Project Backend
 * Requirements Implemented:
 * 1. User Authentication (Bcrypt hashing, JWT)
 * 2. Logging & Security Auditing (MongoDB storage of security events)
 * 3. Key Public Storage (Storing the public half of the asymmetric pair)
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { router: apiRouter, initialize: initializeRoutes } = require('./routes');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173'
}));
app.use(express.json());

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGODB_URI, {
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

// Message Schema (Part 4: End-to-End Encrypted Messages)
const messageSchema = new mongoose.Schema({
    from: { type: String, required: true },
    to: { type: String, required: true },
    encryptedSessionKey: { type: String, required: true }, // AES key encrypted with recipient's RSA public key
    ciphertext: { type: String, required: true }, // Message encrypted with AES-GCM
    iv: { type: String, required: true }, // Initialization Vector for AES-GCM
    authTag: { type: String, required: true }, // Authentication tag from AES-GCM
    nonce: { type: String, required: true }, // For replay attack protection
    timestamp: { type: Date, default: Date.now },
    sequenceNumber: { type: Number, required: true }, // For replay attack protection
});

const User = mongoose.model('User', userSchema);
const AuditLog = mongoose.model('AuditLog', logSchema);
const Message = mongoose.model('Message', messageSchema);

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

// Initialize routes with models and logging function
initializeRoutes(User, AuditLog, Message, createLog);

// Mount API routes
app.use('/api', apiRouter);

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));