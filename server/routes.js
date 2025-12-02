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
let User, AuditLog, Message, File, createLog;

// Initialize function to set dependencies
const initialize = (userModel, auditLogModel, messageModel, fileModel, createLogFn) => {
    User = userModel;
    AuditLog = auditLogModel;
    Message = messageModel;
    File = fileModel;
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

// 7. SEND ENCRYPTED MESSAGE (Part 4)
router.post('/messages', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { to, encryptedSessionKey, ciphertext, iv, authTag, nonce, sequenceNumber, sharedFile } = req.body;

        if (!to || !encryptedSessionKey || !ciphertext || !iv || !authTag || !nonce || sequenceNumber === undefined) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // Check for replay attack: duplicate nonce
        const existingMessage = await Message.findOne({ from: decoded.username, to, nonce });
        if (existingMessage) {
            await createLog(req, 'REPLAY_ATTACK_DETECTED', `Duplicate nonce detected from ${decoded.username} to ${to}`, decoded.username, 'critical');
            return res.status(400).json({ message: "Replay attack detected: duplicate nonce" });
        }

        // Check sequence number (should be incrementing)
        const lastMessage = await Message.findOne({ from: decoded.username, to }).sort({ sequenceNumber: -1 });
        if (lastMessage && sequenceNumber <= lastMessage.sequenceNumber) {
            await createLog(req, 'REPLAY_ATTACK_DETECTED', `Invalid sequence number from ${decoded.username} to ${to}`, decoded.username, 'critical');
            return res.status(400).json({ message: "Replay attack detected: invalid sequence" });
        }

        // Check timestamp (message shouldn't be older than 5 minutes)
        const messageAge = Date.now() - new Date(req.body.timestamp || Date.now()).getTime();
        if (messageAge > 5 * 60 * 1000) {
            await createLog(req, 'REPLAY_ATTACK_DETECTED', `Old timestamp from ${decoded.username} to ${to}`, decoded.username, 'warning');
            return res.status(400).json({ message: "Message timestamp too old" });
        }

        // Store encrypted message (server cannot decrypt it!)
        const message = new Message({
            from: decoded.username,
            to,
            encryptedSessionKey,
            ciphertext,
            iv,
            authTag,
            nonce,
            sequenceNumber,
            timestamp: new Date(),
            sharedFile: sharedFile || null // Include file metadata if present
        });

        await message.save();

        await createLog(req, 'MESSAGE_SENT', `Encrypted message sent from ${decoded.username} to ${to}`, decoded.username, 'info');
        
        res.status(201).json({ message: "Message sent successfully", messageId: message._id });

    } catch (err) {
        console.error("Send message error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// 8. GET MESSAGES (Part 4)
router.get('/messages/:otherUsername', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const otherUsername = req.params.otherUsername;

        // Fetch messages between current user and other user (both directions)
        const messages = await Message.find({
            $or: [
                { from: decoded.username, to: otherUsername },
                { from: otherUsername, to: decoded.username }
            ]
        }).sort({ timestamp: 1 });

        await createLog(req, 'MESSAGES_RETRIEVED', `User ${decoded.username} retrieved messages with ${otherUsername}`, decoded.username, 'info');
        
        res.json(messages);

    } catch (err) {
        console.error("Get messages error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

/**
 * =====================================================
 * PART 5: END-TO-END ENCRYPTED FILE SHARING ROUTES
 * All file operations preserve end-to-end encryption
 * Server stores only encrypted data - cannot decrypt
 * =====================================================
 */

// 9. UPLOAD ENCRYPTED FILE (Part 5)
// Client sends pre-encrypted file chunks
// Server stores them without access to encryption keys
router.post('/files/upload', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const sender = decoded.username;

        const {
            fileName,
            fileSize,
            fileType,
            totalChunks,
            chunkSize,
            encryptedAESKey,
            encryptedChunks,
            recipientUsername
        } = req.body;

        // Validate recipient exists
        const recipient = await User.findOne({ username: recipientUsername });
        if (!recipient) {
            await createLog(req, 'FILE_UPLOAD_FAIL', `Recipient ${recipientUsername} not found`, sender, 'warning');
            return res.status(404).json({ message: "Recipient not found" });
        }

        // Create file document with encrypted chunks
        const fileDoc = new File({
            fileName,
            fileSize,
            fileType,
            from: sender,
            to: recipientUsername,
            totalChunks,
            chunkSize,
            encryptedAESKey, // AES key encrypted with recipient's RSA public key
            encryptedChunks // Array of encrypted chunks with IV and auth tags
        });

        await fileDoc.save();

        await createLog(req, 'FILE_UPLOADED', `File "${fileName}" (${fileSize} bytes, ${totalChunks} chunks) uploaded from ${sender} to ${recipientUsername}`, sender, 'info');

        res.status(201).json({
            message: "File uploaded successfully",
            fileId: fileDoc._id,
            totalChunks: encryptedChunks.length
        });

    } catch (err) {
        console.error("File upload error:", err);
        await createLog(req, 'FILE_UPLOAD_ERROR', `File upload error: ${err.message}`, null, 'critical');
        res.status(500).json({ message: "File upload failed" });
    }
});

// 10. GET SHARED FILES LIST (Part 5)
// Returns list of files shared with the current user
// All file content remains encrypted
router.get('/files', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const recipient = decoded.username;

        // Fetch all files shared with this user
        const files = await File.find({ to: recipient }).select(
            'fileName fileSize fileType from uploadedAt isDownloaded totalChunks _id'
        ).sort({ uploadedAt: -1 });

        await createLog(req, 'FILES_LIST_RETRIEVED', `User ${recipient} retrieved shared files list (${files.length} files)`, recipient, 'info');

        res.json(files);

    } catch (err) {
        console.error("Get files error:", err);
        res.status(500).json({ message: "Failed to retrieve files" });
    }
});

// 11. DOWNLOAD ENCRYPTED FILE (Part 5)
// Returns fully encrypted file metadata and chunks
// Client decrypts using their private key
router.get('/files/download/:fileId', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const recipient = decoded.username;
        const fileId = req.params.fileId;

        // Find file
        const file = await File.findById(fileId);
        if (!file) {
            await createLog(req, 'FILE_DOWNLOAD_FAIL', `File ${fileId} not found`, recipient, 'warning');
            return res.status(404).json({ message: "File not found" });
        }

        // Verify recipient is authorized to download
        if (file.to !== recipient) {
            await createLog(req, 'FILE_DOWNLOAD_UNAUTHORIZED', `Unauthorized download attempt for file ${fileId} by ${recipient}`, recipient, 'warning');
            return res.status(403).json({ message: "Unauthorized to download this file" });
        }

        // Increment download count and mark as downloaded
        file.downloads = (file.downloads || 0) + 1;
        file.isDownloaded = true;
        await file.save();

        // Return encrypted file metadata and chunks
        // Client will use their private key to decrypt the AES key
        // Then use AES key to decrypt each chunk
        await createLog(req, 'FILE_DOWNLOADED', `File "${file.fileName}" downloaded by ${recipient}`, recipient, 'info');

        res.json({
            fileName: file.fileName,
            fileSize: file.fileSize,
            fileType: file.fileType,
            from: file.from,
            totalChunks: file.totalChunks,
            chunkSize: file.chunkSize,
            encryptedAESKey: file.encryptedAESKey, // Encrypted with recipient's RSA key
            encryptedChunks: file.encryptedChunks, // Each chunk encrypted with AES-256-GCM
            uploadedAt: file.uploadedAt
        });

    } catch (err) {
        console.error("File download error:", err);
        res.status(500).json({ message: "File download failed" });
    }
});

// 12. DELETE FILE (Part 5)
// Only sender can delete shared files
router.delete('/files/:fileId', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.sendStatus(401);

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const sender = decoded.username;
        const fileId = req.params.fileId;

        // Find file
        const file = await File.findById(fileId);
        if (!file) {
            await createLog(req, 'FILE_DELETE_FAIL', `File ${fileId} not found`, sender, 'warning');
            return res.status(404).json({ message: "File not found" });
        }

        // Verify sender is authorized to delete
        if (file.from !== sender) {
            await createLog(req, 'FILE_DELETE_UNAUTHORIZED', `Unauthorized delete attempt for file ${fileId} by ${sender}`, sender, 'warning');
            return res.status(403).json({ message: "Only sender can delete files" });
        }

        // Delete file
        await File.findByIdAndDelete(fileId);

        await createLog(req, 'FILE_DELETED', `File "${file.fileName}" deleted by ${sender}`, sender, 'info');

        res.json({ message: "File deleted successfully" });

    } catch (err) {
        console.error("File delete error:", err);
        res.status(500).json({ message: "File deletion failed" });
    }
});

module.exports = { router, initialize };
