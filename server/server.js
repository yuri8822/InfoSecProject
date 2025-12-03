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
// Increase JSON payload limit for encrypted file uploads (PART 5)
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb' }));

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
    publicKey: { type: Object, required: true }, // RSA public key (JWK Format)
    longTermSigningPublicKey: { type: Object }, // ECDSA public key (JWK Format) for key exchange
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
    encryptedSessionKey: { type: String }, // AES key encrypted with recipient's RSA public key (optional for session key messages)
    ciphertext: { type: String, required: true }, // Message encrypted with AES-GCM
    iv: { type: String, required: true }, // Initialization Vector for AES-GCM
    authTag: { type: String, required: true }, // Authentication tag from AES-GCM
    nonce: { type: String, required: true }, // For replay attack protection
    timestamp: { type: Date, default: Date.now },
    sequenceNumber: { type: Number, required: true }, // For replay attack protection
    usesSessionKey: { type: Boolean, default: false }, // Flag for session key usage (from key exchange)
    sharedFile: { // Optional: file shared with this message
        fileId: { type: String }, // Reference to File document
        fileName: { type: String },
        fileSize: { type: Number },
        fileType: { type: String }
    }
});

/**
 * PART 5: File Schema for End-to-End Encrypted File Sharing
 * Stores encrypted files with metadata
 * Only server stores encrypted chunks - cannot decrypt them
 * Decryption happens exclusively on client-side
 */
const fileSchema = new mongoose.Schema({
    fileName: { type: String, required: true }, // Original file name (encrypted with AES by client)
    fileSize: { type: Number, required: true }, // Original file size
    fileType: { type: String }, // MIME type
    from: { type: String, required: true }, // Sender username
    to: { type: String, required: true }, // Recipient username
    totalChunks: { type: Number, required: true }, // Number of encrypted chunks
    chunkSize: { type: Number, required: true }, // Size of each chunk in bytes
    encryptedAESKey: { type: String, required: true }, // AES key encrypted with recipient's RSA public key
    encryptedChunks: [{
        chunkIndex: { type: Number, required: true },
        ciphertext: { type: String, required: true }, // Encrypted chunk (Base64)
        iv: { type: String, required: true }, // Initialization Vector (Base64)
        authTag: { type: String, required: true }, // Authentication tag (Base64)
        chunkSize: { type: Number }
    }],
    uploadedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }, // 30-day expiry
    downloads: { type: Number, default: 0 }, // Track number of downloads
    isDownloaded: { type: Boolean, default: false } // Mark if recipient has downloaded
});

const keyExchangeSessionSchema = new mongoose.Schema({
    sessionId: { type: String, required: true, unique: true },
    initiator: { type: String, required: true },
    responder: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['hello_sent', 'response_sent', 'confirmed', 'failed', 'expired'],
        default: 'hello_sent'
    },
    kxHello: {
        id: String,
        ephPub: Object, // Ephemeral ECDH public key (JWK)
        longTermPub: Object, // Long-term ECDSA public key (JWK)
        nonce: String,
        signature: String
    },
    kxResponse: {
        id: String,
        ephPub: Object,
        longTermPub: Object,
        nonce: String,
        signature: String
    },
    kxConfirm: {
        confirmTag: String, // HMAC confirmation tag
        from: String // Who sent the confirmation
    },
    salt: { type: String }, // HKDF salt (shared between parties)
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 5 * 60 * 1000) }, // 5 min expiry
    completedAt: { type: Date }
});

const User = mongoose.model('User', userSchema);
const AuditLog = mongoose.model('AuditLog', logSchema);
const Message = mongoose.model('Message', messageSchema);
const File = mongoose.model('File', fileSchema);
const KeyExchangeSession = mongoose.model('KeyExchangeSession', keyExchangeSessionSchema);

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

initializeRoutes(User, AuditLog, Message, File, KeyExchangeSession, createLog);

app.use('/api', apiRouter);

app.listen(PORT, () => console.log(`Secure Server running on port ${PORT}`));