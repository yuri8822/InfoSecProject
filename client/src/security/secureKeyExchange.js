// [3] secureKeyExchange.js

const crypto = require("crypto");

// Key Pair Utility Functions.

function generateLongTermKeyPair() {
  // Generate Ed25519 signing key pair.
  return crypto.generateKeyPairSync("ed25519");
}

function signData(privateKey, data) {
  // Sign data with Ed25519.
  return crypto.sign(null, Buffer.from(data), privateKey);
}

function verifySignature(publicKey, data, signature) {
  // Verify Ed25519 signature.
  return crypto.verify(null, Buffer.from(data), publicKey, signature);
}

// Ephemeral Elliptic Curve Diffie-Helman (ECDH) Utilities.

function generateEphemeralECDH() {
  // X25519 ephemeral key pair.
  const ecdh = crypto.createECDH("x25519");
  ecdh.generateKeys();
  return ecdh;
}

function computeSharedSecret(ecdh, peerPublicKey) {
  // Compute shared secret from peer ephemeral public key.
  return ecdh.computeSecret(peerPublicKey);
}

// HKDF Key Derivation.

function deriveSessionKey(sharedSecret, salt, info) {
  // Derive 32-byte session key from shared secret.
  return crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from(info), 32);
}

// Key Confirmation.

function computeKeyConfirmation(sessionKey, label, transcriptHash, clientId) {
  // Compute HMAC for key confirmation.
  const hmac = crypto.createHmac("sha256", sessionKey);
  hmac.update(label);
  hmac.update(transcriptHash);
  hmac.update(clientId);
  return hmac.digest();
}

function verifyKeyConfirmation(sessionKey, label, transcriptHash, clientId, receivedKC) {
  // Verify received key confirmation HMAC.
  const expected = computeKeyConfirmation(sessionKey, label, transcriptHash, clientId);
  return crypto.timingSafeEqual(expected, receivedKC);
}

// Hash Utility.

function hashData(data) {
  // SHA256 hash.
  return crypto.createHash("sha256").update(data).digest();
}

// Custom Key Exchange Protocol Module.

class KeyExchange {
  constructor(clientId, longTermKeys) {
    this.clientId = clientId;
    this.longTermKeys = longTermKeys; // {privateKey, publicKey}
    this.ephemeral = generateEphemeralECDH();
    this.nonce = crypto.randomBytes(16);
    this.peerId = null;
    this.peerEphemeral = null;
    this.peerNonce = null;
    this.sessionKey = null;
  }

  createInitMessage() {
    // Message to initiate key exchange.
    const message = Buffer.concat([Buffer.from(this.clientId), this.ephemeral.getPublicKey(), this.nonce]);
    const signature = signData(this.longTermKeys.privateKey, message);
    return {
      id: this.clientId,
      ephPub: this.ephemeral.getPublicKey(),
      nonce: this.nonce,
      signature: signature
    };
  }

  processInitMessage(msg, peerPublicKey) {
    // Verify peer signature and store ephemeral/nonce.
    const verify = verifySignature(peerPublicKey, Buffer.concat([Buffer.from(msg.id), msg.ephPub, msg.nonce]), msg.signature);
    if (!verify) throw new Error("Invalid signature from peer");
    this.peerId = msg.id;
    this.peerEphemeral = msg.ephPub;
    this.peerNonce = msg.nonce;
  }

  createResponseMessage(peerInitMessage, peerPublicKey) {
    // Create response message including signature of peer ephemeral + nonce.
    this.processInitMessage(peerInitMessage, peerPublicKey);
    const message = Buffer.concat([Buffer.from(this.clientId), this.ephemeral.getPublicKey(), this.nonce, this.peerEphemeral, this.peerNonce]);
    const signature = signData(this.longTermKeys.privateKey, message);
    return {
      id: this.clientId,
      ephPub: this.ephemeral.getPublicKey(),
      nonce: this.nonce,
      signature: signature
    };
  }

  finalizeSession(peerResponseMessage, peerPublicKey) {
    // Verify peer response and compute session key.
    const message = Buffer.concat([Buffer.from(peerResponseMessage.id), peerResponseMessage.ephPub, peerResponseMessage.nonce, this.ephemeral.getPublicKey(), this.nonce]);
    const verify = verifySignature(peerPublicKey, message, peerResponseMessage.signature);
    if (!verify) throw new Error("Invalid signature from peer");
    this.peerEphemeral = peerResponseMessage.ephPub;
    this.peerNonce = peerResponseMessage.nonce;

    const sharedSecret = computeSharedSecret(this.ephemeral, this.peerEphemeral);
    const salt = hashData(Buffer.concat([this.nonce, this.peerNonce]));
    const transcript = Buffer.concat([this.ephemeral.getPublicKey(), this.nonce, this.peerEphemeral, this.peerNonce]);
    const info = "E2EE-Prot v1" + this.clientId + this.peerId;
    this.sessionKey = deriveSessionKey(sharedSecret, salt, info);
    return this.sessionKey;
  }

  createKeyConfirmation(label) {
    // Compute key confirmation HMAC.
    const transcript = Buffer.concat([this.ephemeral.getPublicKey(), this.nonce, this.peerEphemeral, this.peerNonce]);
    const transcriptHash = hashData(transcript);
    return computeKeyConfirmation(this.sessionKey, label, transcriptHash, this.clientId);
  }

  verifyKeyConfirmation(label, receivedKC, peerId) {
    const transcript = Buffer.concat([this.ephemeral.getPublicKey(), this.nonce, this.peerEphemeral, this.peerNonce]);
    const transcriptHash = hashData(transcript);
    return verifyKeyConfirmation(this.sessionKey, label, transcriptHash, peerId, receivedKC);
  }

  getSessionKey() {
    return this.sessionKey;
  }
}

// Export Module.
module.exports = { 
  KeyExchange,
  generateLongTermKeyPair,
  signData,
  verifySignature
};

