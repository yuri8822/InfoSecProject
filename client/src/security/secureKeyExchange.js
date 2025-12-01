// [3] secureKeyExchange.js - Browser-compatible Web Crypto API version

// Key Pair Utility Functions.

/**
 * Generate Ed25519 signing key pair using Web Crypto API
 * @returns {Promise<CryptoKeyPair>} {privateKey, publicKey}
 */
async function generateLongTermKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "Ed25519"
    },
    true, // extractable
    ["sign", "verify"]
  );
}

/**
 * Sign data with Ed25519 private key
 * @param {CryptoKey} privateKey - Ed25519 private key
 * @param {Uint8Array|ArrayBuffer} data - Data to sign
 * @returns {Promise<ArrayBuffer>} Signature
 */
async function signData(privateKey, data) {
  const dataBuffer = data instanceof ArrayBuffer ? data : new Uint8Array(data).buffer;
  return await window.crypto.subtle.sign(
    {
      name: "Ed25519"
    },
    privateKey,
    dataBuffer
  );
}

/**
 * Verify Ed25519 signature
 * @param {CryptoKey} publicKey - Ed25519 public key
 * @param {Uint8Array|ArrayBuffer} data - Original data
 * @param {Uint8Array|ArrayBuffer} signature - Signature to verify
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifySignature(publicKey, data, signature) {
  const dataBuffer = data instanceof ArrayBuffer ? data : new Uint8Array(data).buffer;
  const sigBuffer = signature instanceof ArrayBuffer ? signature : new Uint8Array(signature).buffer;
  return await window.crypto.subtle.verify(
    {
      name: "Ed25519"
    },
    publicKey,
    sigBuffer,
    dataBuffer
  );
}

// Ephemeral Elliptic Curve Diffie-Hellman (ECDH) Utilities.

/**
 * Generate X25519 ephemeral key pair
 * @returns {Promise<CryptoKeyPair>} {privateKey, publicKey}
 */
async function generateEphemeralECDH() {
  return await window.crypto.subtle.generateKey(
    {
      name: "X25519"
    },
    true, // extractable
    ["deriveKey", "deriveBits"]
  );
}

/**
 * Compute shared secret from X25519 key pair and peer public key
 * @param {CryptoKeyPair} keyPair - Our X25519 key pair
 * @param {CryptoKey} peerPublicKey - Peer's X25519 public key
 * @returns {Promise<ArrayBuffer>} Shared secret (32 bytes)
 */
async function computeSharedSecret(keyPair, peerPublicKey) {
  return await window.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: peerPublicKey
    },
    keyPair.privateKey,
    256 // 32 bytes = 256 bits
  );
}

// HKDF Key Derivation.

/**
 * Derive session key using HKDF
 * @param {ArrayBuffer} sharedSecret - Shared secret from ECDH
 * @param {Uint8Array|ArrayBuffer} salt - Salt for HKDF
 * @param {string} info - Info string for HKDF
 * @returns {Promise<ArrayBuffer>} Derived 32-byte session key
 */
async function deriveSessionKey(sharedSecret, salt, info) {
  // Import shared secret as a key for HKDF
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    sharedSecret,
    {
      name: "HKDF",
      hash: "SHA-256"
    },
    false,
    ["deriveBits"]
  );

  const saltBuffer = salt instanceof ArrayBuffer ? salt : new Uint8Array(salt).buffer;
  const infoBuffer = new TextEncoder().encode(info);

  // Derive key using HKDF
  return await window.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: saltBuffer,
      info: infoBuffer
    },
    baseKey,
    256 // 32 bytes = 256 bits
  );
}

// Key Confirmation.

/**
 * Compute HMAC for key confirmation
 * @param {ArrayBuffer} sessionKey - Session key
 * @param {string} label - Label for key confirmation
 * @param {Uint8Array|ArrayBuffer} transcriptHash - Hash of transcript
 * @param {string} clientId - Client ID
 * @returns {Promise<ArrayBuffer>} HMAC digest
 */
async function computeKeyConfirmation(sessionKey, label, transcriptHash, clientId) {
  // Import session key as HMAC key
  const hmacKey = await window.crypto.subtle.importKey(
    "raw",
    sessionKey,
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  // Concatenate inputs
  const labelBytes = new TextEncoder().encode(label);
  const transcriptHashBuffer = transcriptHash instanceof ArrayBuffer 
    ? new Uint8Array(transcriptHash) 
    : new Uint8Array(transcriptHash);
  const clientIdBytes = new TextEncoder().encode(clientId);

  const data = new Uint8Array(labelBytes.length + transcriptHashBuffer.length + clientIdBytes.length);
  data.set(labelBytes, 0);
  data.set(transcriptHashBuffer, labelBytes.length);
  data.set(clientIdBytes, labelBytes.length + transcriptHashBuffer.length);

  // Compute HMAC
  return await window.crypto.subtle.sign(
    {
      name: "HMAC"
    },
    hmacKey,
    data.buffer
  );
}

/**
 * Verify key confirmation HMAC
 * @param {ArrayBuffer} sessionKey - Session key
 * @param {string} label - Label for key confirmation
 * @param {Uint8Array|ArrayBuffer} transcriptHash - Hash of transcript
 * @param {string} clientId - Client ID
 * @param {Uint8Array|ArrayBuffer} receivedKC - Received key confirmation
 * @returns {Promise<boolean>} True if key confirmation is valid
 */
async function verifyKeyConfirmation(sessionKey, label, transcriptHash, clientId, receivedKC) {
  const expected = await computeKeyConfirmation(sessionKey, label, transcriptHash, clientId);
  
  // Timing-safe comparison
  const expectedArray = new Uint8Array(expected);
  const receivedArray = receivedKC instanceof ArrayBuffer 
    ? new Uint8Array(receivedKC) 
    : new Uint8Array(receivedKC);

  if (expectedArray.length !== receivedArray.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < expectedArray.length; i++) {
    result |= expectedArray[i] ^ receivedArray[i];
  }
  return result === 0;
}

// Hash Utility.

/**
 * Hash data using SHA-256
 * @param {Uint8Array|ArrayBuffer} data - Data to hash
 * @returns {Promise<ArrayBuffer>} Hash digest
 */
async function hashData(data) {
  const dataBuffer = data instanceof ArrayBuffer ? data : new Uint8Array(data).buffer;
  return await window.crypto.subtle.digest("SHA-256", dataBuffer);
}

// Helper function to convert ArrayBuffer to base64 for JSON serialization
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper function to convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper function to export public key to JWK format
async function exportPublicKey(publicKey) {
  return await window.crypto.subtle.exportKey("jwk", publicKey);
}

// Helper function to import public key from JWK format
async function importPublicKey(jwk) {
  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "Ed25519"
    },
    true,
    ["verify"]
  );
}

// Helper function to import X25519 public key from raw bytes
async function importX25519PublicKey(rawKey) {
  return await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    {
      name: "X25519"
    },
    true,
    []
  );
}

// Custom Key Exchange Protocol Module.

class KeyExchange {
  constructor(clientId, longTermKeys) {
    this.clientId = clientId;
    this.longTermKeys = longTermKeys; // {privateKey, publicKey} - Ed25519 keys
    this.ephemeral = null; // Will be set when generateEphemeral is called
    this.nonce = null; // Will be set when generateNonce is called
    this.peerId = null;
    this.peerEphemeral = null;
    this.peerNonce = null;
    this.sessionKey = null;
  }

  /**
   * Generate ephemeral key pair and nonce (call before createInitMessage)
   */
  async generateEphemeral() {
    this.ephemeral = await generateEphemeralECDH();
    this.nonce = new Uint8Array(16);
    window.crypto.getRandomValues(this.nonce);
  }

  /**
   * Create initialization message to start key exchange
   * @returns {Promise<Object>} Init message with id, ephPub, nonce, signature
   */
  async createInitMessage() {
    if (!this.ephemeral || !this.nonce) {
      await this.generateEphemeral();
    }

    // Get ephemeral public key as raw bytes
    const ephPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ephPubArray = new Uint8Array(ephPubKey);

    // Concatenate: clientId + ephemeral public key + nonce
    const clientIdBytes = new TextEncoder().encode(this.clientId);
    const message = new Uint8Array(clientIdBytes.length + ephPubArray.length + this.nonce.length);
    message.set(clientIdBytes, 0);
    message.set(ephPubArray, clientIdBytes.length);
    message.set(this.nonce, clientIdBytes.length + ephPubArray.length);

    // Sign the message
    const signature = await signData(this.longTermKeys.privateKey, message.buffer);

    // Export ephemeral public key as base64 for JSON
    return {
      id: this.clientId,
      ephPub: arrayBufferToBase64(ephPubKey),
      nonce: arrayBufferToBase64(this.nonce.buffer),
      signature: arrayBufferToBase64(signature)
    };
  }

  /**
   * Process received initialization message
   * @param {Object} msg - Init message from peer
   * @param {Object} peerPublicKeyJwk - Peer's Ed25519 public key in JWK format
   */
  async processInitMessage(msg, peerPublicKeyJwk) {
    // Import peer's public key
    const peerPublicKey = await importPublicKey(peerPublicKeyJwk);

    // Convert base64 strings back to ArrayBuffers
    const ephPubBuffer = base64ToArrayBuffer(msg.ephPub);
    const nonceBuffer = base64ToArrayBuffer(msg.nonce);
    const signatureBuffer = base64ToArrayBuffer(msg.signature);

    // Reconstruct the message that was signed
    const clientIdBytes = new TextEncoder().encode(msg.id);
    const message = new Uint8Array(clientIdBytes.length + ephPubBuffer.byteLength + nonceBuffer.byteLength);
    message.set(clientIdBytes, 0);
    message.set(new Uint8Array(ephPubBuffer), clientIdBytes.length);
    message.set(new Uint8Array(nonceBuffer), clientIdBytes.length + ephPubBuffer.byteLength);

    // Verify signature
    const verify = await verifySignature(peerPublicKey, message.buffer, signatureBuffer);
    if (!verify) throw new Error("Invalid signature from peer");

    this.peerId = msg.id;
    this.peerEphemeral = ephPubBuffer; // Store as ArrayBuffer for later use
    this.peerNonce = new Uint8Array(nonceBuffer);
  }

  /**
   * Create response message after receiving init message
   * @param {Object} peerInitMessage - Peer's init message
   * @param {Object} peerPublicKeyJwk - Peer's Ed25519 public key in JWK format
   * @returns {Promise<Object>} Response message
   */
  async createResponseMessage(peerInitMessage, peerPublicKeyJwk) {
    // Process and verify peer's init message
    await this.processInitMessage(peerInitMessage, peerPublicKeyJwk);

    // Generate our ephemeral if not already done
    if (!this.ephemeral || !this.nonce) {
      await this.generateEphemeral();
    }

    // Get our ephemeral public key
    const ephPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ephPubArray = new Uint8Array(ephPubKey);

    // Concatenate: clientId + our ephPub + our nonce + peer ephPub + peer nonce
    const clientIdBytes = new TextEncoder().encode(this.clientId);
    const message = new Uint8Array(
      clientIdBytes.length + 
      ephPubArray.length + 
      this.nonce.length + 
      this.peerEphemeral.byteLength + 
      this.peerNonce.length
    );
    let offset = 0;
    message.set(clientIdBytes, offset);
    offset += clientIdBytes.length;
    message.set(ephPubArray, offset);
    offset += ephPubArray.length;
    message.set(this.nonce, offset);
    offset += this.nonce.length;
    message.set(new Uint8Array(this.peerEphemeral), offset);
    offset += this.peerEphemeral.byteLength;
    message.set(this.peerNonce, offset);

    // Sign the message
    const signature = await signData(this.longTermKeys.privateKey, message.buffer);

    return {
      id: this.clientId,
      ephPub: arrayBufferToBase64(ephPubKey),
      nonce: arrayBufferToBase64(this.nonce.buffer),
      signature: arrayBufferToBase64(signature)
    };
  }

  /**
   * Finalize session after receiving response message
   * @param {Object} peerResponseMessage - Peer's response message
   * @param {Object} peerPublicKeyJwk - Peer's Ed25519 public key in JWK format
   * @returns {Promise<ArrayBuffer>} Session key
   */
  async finalizeSession(peerResponseMessage, peerPublicKeyJwk) {
    // Import peer's public key
    const peerPublicKey = await importPublicKey(peerPublicKeyJwk);

    // Convert base64 to ArrayBuffers
    const peerEphPubBuffer = base64ToArrayBuffer(peerResponseMessage.ephPub);
    const peerNonceBuffer = base64ToArrayBuffer(peerResponseMessage.nonce);
    const signatureBuffer = base64ToArrayBuffer(peerResponseMessage.signature);

    // Get our ephemeral public key
    const ourEphPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ourEphPubArray = new Uint8Array(ourEphPubKey);

    // Reconstruct the message that was signed
    const peerIdBytes = new TextEncoder().encode(peerResponseMessage.id);
    const message = new Uint8Array(
      peerIdBytes.length + 
      peerEphPubBuffer.byteLength + 
      peerNonceBuffer.byteLength + 
      ourEphPubArray.length + 
      this.nonce.length
    );
    let offset = 0;
    message.set(peerIdBytes, offset);
    offset += peerIdBytes.length;
    message.set(new Uint8Array(peerEphPubBuffer), offset);
    offset += peerEphPubBuffer.byteLength;
    message.set(new Uint8Array(peerNonceBuffer), offset);
    offset += peerNonceBuffer.byteLength;
    message.set(ourEphPubArray, offset);
    offset += ourEphPubArray.length;
    message.set(this.nonce, offset);

    // Verify signature
    const verify = await verifySignature(peerPublicKey, message.buffer, signatureBuffer);
    if (!verify) throw new Error("Invalid signature from peer");

    // Store peer's ephemeral and nonce
    this.peerEphemeral = peerEphPubBuffer;
    this.peerNonce = new Uint8Array(peerNonceBuffer);

    // Import peer's ephemeral public key for ECDH
    const peerEphPubKey = await importX25519PublicKey(peerEphPubBuffer);

    // Compute shared secret
    const sharedSecret = await computeSharedSecret(this.ephemeral, peerEphPubKey);

    // Derive session key
    const salt = await hashData(
      new Uint8Array([...this.nonce, ...this.peerNonce]).buffer
    );
    const transcript = new Uint8Array([
      ...ourEphPubArray,
      ...this.nonce,
      ...new Uint8Array(peerEphPubBuffer),
      ...this.peerNonce
    ]);
    const info = "E2EE-Prot v1" + this.clientId + this.peerId;
    this.sessionKey = await deriveSessionKey(sharedSecret, salt, info);

    return this.sessionKey;
  }

  /**
   * Create key confirmation HMAC
   * @param {string} label - Label (e.g., "client" or "server")
   * @returns {Promise<ArrayBuffer>} Key confirmation HMAC
   */
  async createKeyConfirmation(label) {
    if (!this.sessionKey) throw new Error("Session key not established");

    const ourEphPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ourEphPubArray = new Uint8Array(ourEphPubKey);
    const transcript = new Uint8Array([
      ...ourEphPubArray,
      ...this.nonce,
      ...new Uint8Array(this.peerEphemeral),
      ...this.peerNonce
    ]);
    const transcriptHash = await hashData(transcript.buffer);
    return await computeKeyConfirmation(this.sessionKey, label, transcriptHash, this.clientId);
  }

  /**
   * Verify key confirmation from peer
   * @param {string} label - Label used by peer
   * @param {Uint8Array|ArrayBuffer} receivedKC - Received key confirmation
   * @param {string} peerId - Peer's ID
   * @returns {Promise<boolean>} True if key confirmation is valid
   */
  async verifyKeyConfirmation(label, receivedKC, peerId) {
    if (!this.sessionKey) throw new Error("Session key not established");

    const ourEphPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ourEphPubArray = new Uint8Array(ourEphPubKey);
    const transcript = new Uint8Array([
      ...ourEphPubArray,
      ...this.nonce,
      ...new Uint8Array(this.peerEphemeral),
      ...this.peerNonce
    ]);
    const transcriptHash = await hashData(transcript.buffer);
    
    const kcBuffer = receivedKC instanceof ArrayBuffer 
      ? receivedKC 
      : base64ToArrayBuffer(receivedKC);
    
    return await verifyKeyConfirmation(this.sessionKey, label, transcriptHash, peerId, kcBuffer);
  }

  /**
   * Get the established session key
   * @returns {ArrayBuffer|null} Session key or null if not established
   */
  getSessionKey() {
    return this.sessionKey;
  }
}

// Export Module (ES6)
export { 
  KeyExchange,
  generateLongTermKeyPair,
  signData,
  verifySignature,
  exportPublicKey,
  importPublicKey
};
