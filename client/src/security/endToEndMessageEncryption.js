const crypto = require("crypto");

// AES-256-GCM based end-to-end message encryption helpers.
// This module is designed to work with the 32-byte sessionKey
// derived by the KeyExchange in `secureKeyExchange.js`.
//
// SECURITY REQUIREMENTS IMPLEMENTED:
// - Algorithm: AES-256-GCM
// - Fresh random IV per message (12 bytes)
// - Authentication tag (MAC) for integrity
// - Server should only ever store: { ciphertext, iv, authTag, metadata }
//   and MUST NOT store any plaintext or session keys.

const ALGO = "aes-256-gcm";
const IV_LENGTH = 12; // 96-bit IV is standard for GCM
const KEY_LENGTH = 32; // 256-bit key

function toBufferKey(sessionKey) {
  // Accept a Buffer, Uint8Array, or hex/base64 string and normalize to Buffer.
  if (!sessionKey) {
    throw new Error("sessionKey is required for encryption/decryption");
  }

  if (Buffer.isBuffer(sessionKey)) {
    if (sessionKey.length !== KEY_LENGTH) {
      throw new Error("sessionKey must be 32 bytes (256 bits)");
    }
    return sessionKey;
  }

  if (sessionKey instanceof Uint8Array) {
    if (sessionKey.length !== KEY_LENGTH) {
      throw new Error("sessionKey must be 32 bytes (256 bits)");
    }
    return Buffer.from(sessionKey);
  }

  if (typeof sessionKey === "string") {
    // Try hex first, then base64.
    let keyBuf;
    try {
      keyBuf = Buffer.from(sessionKey, "hex");
    } catch (_) {}
    if (!keyBuf || keyBuf.length !== KEY_LENGTH) {
      keyBuf = Buffer.from(sessionKey, "base64");
    }
    if (keyBuf.length !== KEY_LENGTH) {
      throw new Error("sessionKey string must decode to 32 bytes");
    }
    return keyBuf;
  }

  throw new Error("Unsupported sessionKey type");
}

function normalizeAAD(metadata) {
  // Additional Authenticated Data (AAD) binds metadata to the ciphertext.
  // This is not secret, but any tampering will be detected.
  if (metadata == null) return null;

  if (Buffer.isBuffer(metadata)) return metadata;
  if (metadata instanceof Uint8Array) return Buffer.from(metadata);
  if (typeof metadata === "string") return Buffer.from(metadata, "utf8");

  // For objects, JSON-encode deterministically.
  try {
    const json = JSON.stringify(metadata);
    return Buffer.from(json, "utf8");
  } catch (_) {
    return null;
  }
}

/**
 * Encrypt a plaintext message with AES-256-GCM.
 *
 * @param {Buffer|string|Uint8Array} sessionKey - 32-byte key from KeyExchange.getSessionKey().
 * @param {string|Buffer|Uint8Array} plaintext - Message content to encrypt.
 * @param {object|string|Buffer} [metadata] - Non-secret metadata (sender/receiver IDs, timestamp, etc.).
 *   This will be returned unchanged and used as AAD (integrity-protected but not encrypted).
 *
 * @returns {{ciphertext: string, iv: string, authTag: string, metadata: any}}
 *   - ciphertext, iv, authTag are base64-encoded strings suitable for storage/transmission.
 *   - metadata is echoed back as-is so the caller can store it alongside the ciphertext.
 */
function encryptMessage(sessionKey, plaintext, metadata) {
  const key = toBufferKey(sessionKey);

  // Normalize plaintext to Buffer.
  let plainBuf;
  if (Buffer.isBuffer(plaintext)) {
    plainBuf = plaintext;
  } else if (plaintext instanceof Uint8Array) {
    plainBuf = Buffer.from(plaintext);
  } else if (typeof plaintext === "string") {
    plainBuf = Buffer.from(plaintext, "utf8");
  } else {
    throw new Error("Unsupported plaintext type");
  }

  // Fresh random IV per message.
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGO, key, iv);

  const aad = normalizeAAD(metadata);
  if (aad) {
    cipher.setAAD(aad);
  }

  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    // Only store / send these values + metadata on the server.
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    metadata: metadata || null,
  };
}

/**
 * Decrypt an AES-256-GCM encrypted message.
 *
 * @param {Buffer|string|Uint8Array} sessionKey - Same 32-byte key used for encryption.
 * @param {{ciphertext: string, iv: string, authTag: string, metadata?: any}} payload
 *   Object returned by encryptMessage (or loaded from server).
 * @param {object|string|Buffer} [expectedMetadata]
 *   Optional metadata to verify as AAD. If provided, it must match what was used during encryption
 *   or decryption will fail with an authentication error.
 *
 * @returns {string} - Decrypted plaintext as UTF-8 string.
 */
function decryptMessage(sessionKey, payload, expectedMetadata) {
  const key = toBufferKey(sessionKey);

  if (!payload || typeof payload !== "object") {
    throw new Error("Invalid payload for decryption");
  }

  const { ciphertext, iv, authTag } = payload;

  const ivBuf = Buffer.from(iv, "base64");
  const ctBuf = Buffer.from(ciphertext, "base64");
  const tagBuf = Buffer.from(authTag, "base64");

  const decipher = crypto.createDecipheriv(ALGO, key, ivBuf);
  decipher.setAuthTag(tagBuf);

  const aad = normalizeAAD(expectedMetadata != null ? expectedMetadata : payload.metadata);
  if (aad) {
    decipher.setAAD(aad);
  }

  const decrypted = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  return decrypted.toString("utf8");
}

// Example integration (pseudo-code, not executed here):
//
// const { KeyExchange } = require("./secureKeyExchange");
// const { encryptMessage, decryptMessage } = require("./endToEndMessageEncryption");
//
// // After completing the key exchange:
// const sessionKey = keyExchange.getSessionKey(); // 32-byte Buffer
//
// // On sender:
// const metadata = { senderId: "alice", receiverId: "bob", timestamp: Date.now() };
// const encrypted = encryptMessage(sessionKey, "hello bob", metadata);
// // -> Send/store only: encrypted.ciphertext, encrypted.iv, encrypted.authTag, encrypted.metadata
//
// // On receiver (with same sessionKey):
// const plaintext = decryptMessage(sessionKey, encrypted, metadata);
//
// NOTE: The backend should NEVER see or store the plaintext or sessionKey.

module.exports = {
  encryptMessage,
  decryptMessage,
};
