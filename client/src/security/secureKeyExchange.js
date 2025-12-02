// [3] secureKeyExchange.js - Browser-compatible Web Crypto API version

// Key pair utilities for long-term signing keys.

async function generateLongTermKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "Ed25519"
    },
    true, // extractable
    ["sign", "verify"]
  );
}

// Sign data with our Ed25519 private key.
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

// Verify an Ed25519 signature.
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

// Ephemeral ECDH utilities for key exchange.

async function generateEphemeralECDH() {
  return await window.crypto.subtle.generateKey(
    {
      name: "X25519"
    },
    true, // extractable
    ["deriveKey", "deriveBits"]
  );
}

// Compute the shared secret using our ephemeral key and peer's public key.
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

// HKDF key derivation for session keys.

async function deriveSessionKey(sharedSecret, salt, info) {
  // Import the shared secret so we can use it with HKDF.
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

  // Derive the 32-byte session key.
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

// Key confirmation using HMAC.

async function computeKeyConfirmation(sessionKey, label, transcriptHash, clientId) {
  // Import the session key as an HMAC key.
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

  // Concatenate all the inputs.
  const labelBytes = new TextEncoder().encode(label);
  const transcriptHashBuffer = transcriptHash instanceof ArrayBuffer 
    ? new Uint8Array(transcriptHash) 
    : new Uint8Array(transcriptHash);
  const clientIdBytes = new TextEncoder().encode(clientId);

  const data = new Uint8Array(labelBytes.length + transcriptHashBuffer.length + clientIdBytes.length);
  data.set(labelBytes, 0);
  data.set(transcriptHashBuffer, labelBytes.length);
  data.set(clientIdBytes, labelBytes.length + transcriptHashBuffer.length);

  // Compute and return the HMAC.
  return await window.crypto.subtle.sign(
    {
      name: "HMAC"
    },
    hmacKey,
    data.buffer
  );
}

// Verify a key confirmation HMAC from the peer.
async function verifyKeyConfirmation(sessionKey, label, transcriptHash, clientId, receivedKC) {
  const expected = await computeKeyConfirmation(sessionKey, label, transcriptHash, clientId);
  
  // Use timing-safe comparison to prevent timing attacks.
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

// Hash utility functions.

async function hashData(data) {
  const dataBuffer = data instanceof ArrayBuffer ? data : new Uint8Array(data).buffer;
  return await window.crypto.subtle.digest("SHA-256", dataBuffer);
}

// Convert ArrayBuffer to base64 string for JSON serialization.
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert base64 string back to ArrayBuffer.
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Export a public key to JWK format.
async function exportPublicKey(publicKey) {
  return await window.crypto.subtle.exportKey("jwk", publicKey);
}

// Import a public key from JWK format.
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

// Import an X25519 public key from raw bytes.
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

// Custom key exchange protocol implementation.

class KeyExchange {
  constructor(clientId, longTermKeys) {
    this.clientId = clientId;
    this.longTermKeys = longTermKeys; // Ed25519 keys: {privateKey, publicKey}
    this.ephemeral = null; // Generated when needed
    this.nonce = null; // Generated when needed
    this.peerId = null;
    this.peerEphemeral = null;
    this.peerNonce = null;
    this.sessionKey = null;
  }

  // Generate ephemeral key pair and nonce. Call this before createInitMessage.
  async generateEphemeral() {
    this.ephemeral = await generateEphemeralECDH();
    this.nonce = new Uint8Array(16);
    window.crypto.getRandomValues(this.nonce);
  }

  // Create the init message to start key exchange.
  async createInitMessage() {
    if (!this.ephemeral || !this.nonce) {
      await this.generateEphemeral();
    }

    // Get our ephemeral public key as raw bytes.
    const ephPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ephPubArray = new Uint8Array(ephPubKey);

    // Build the message: clientId + ephemeral public key + nonce.
    const clientIdBytes = new TextEncoder().encode(this.clientId);
    const message = new Uint8Array(clientIdBytes.length + ephPubArray.length + this.nonce.length);
    message.set(clientIdBytes, 0);
    message.set(ephPubArray, clientIdBytes.length);
    message.set(this.nonce, clientIdBytes.length + ephPubArray.length);

    // Sign it with our long-term private key.
    const signature = await signData(this.longTermKeys.privateKey, message.buffer);

    // Return everything as base64 strings for JSON.
    return {
      id: this.clientId,
      ephPub: arrayBufferToBase64(ephPubKey),
      nonce: arrayBufferToBase64(this.nonce.buffer),
      signature: arrayBufferToBase64(signature)
    };
  }

  // Process and verify a received init message from the peer.
  async processInitMessage(msg, peerPublicKeyJwk) {
    // Import the peer's public key.
    const peerPublicKey = await importPublicKey(peerPublicKeyJwk);

    // Convert base64 strings back to ArrayBuffers.
    const ephPubBuffer = base64ToArrayBuffer(msg.ephPub);
    const nonceBuffer = base64ToArrayBuffer(msg.nonce);
    const signatureBuffer = base64ToArrayBuffer(msg.signature);

    // Reconstruct the exact message that was signed.
    const clientIdBytes = new TextEncoder().encode(msg.id);
    const message = new Uint8Array(clientIdBytes.length + ephPubBuffer.byteLength + nonceBuffer.byteLength);
    message.set(clientIdBytes, 0);
    message.set(new Uint8Array(ephPubBuffer), clientIdBytes.length);
    message.set(new Uint8Array(nonceBuffer), clientIdBytes.length + ephPubBuffer.byteLength);

    // Verify the signature.
    const verify = await verifySignature(peerPublicKey, message.buffer, signatureBuffer);
    if (!verify) throw new Error("Invalid signature from peer");

    // Store the peer's info for later.
    this.peerId = msg.id;
    this.peerEphemeral = ephPubBuffer;
    this.peerNonce = new Uint8Array(nonceBuffer);
  }

  // Create a response message after receiving the peer's init message.
  async createResponseMessage(peerInitMessage, peerPublicKeyJwk) {
    // First, process and verify the peer's init message.
    await this.processInitMessage(peerInitMessage, peerPublicKeyJwk);

    // Generate our own ephemeral key if we haven't already.
    if (!this.ephemeral || !this.nonce) {
      await this.generateEphemeral();
    }

    // Get our ephemeral public key.
    const ephPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ephPubArray = new Uint8Array(ephPubKey);

    // Build the message: clientId + our ephPub + our nonce + peer ephPub + peer nonce.
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

    // Sign it with our long-term private key.
    const signature = await signData(this.longTermKeys.privateKey, message.buffer);

    return {
      id: this.clientId,
      ephPub: arrayBufferToBase64(ephPubKey),
      nonce: arrayBufferToBase64(this.nonce.buffer),
      signature: arrayBufferToBase64(signature)
    };
  }

  // Derive the session key as the responder (after creating response message).
  // The responder can derive the session key independently since they have all the needed info.
  async deriveSessionKeyAsResponder() {
    if (!this.ephemeral || !this.nonce || !this.peerEphemeral || !this.peerNonce) {
      throw new Error("Missing required data for session key derivation");
    }

    // Import the peer's ephemeral public key for ECDH.
    const peerEphPubKey = await importX25519PublicKey(this.peerEphemeral);

    // Compute the shared secret using ECDH.
    const sharedSecret = await computeSharedSecret(this.ephemeral, peerEphPubKey);

    // Derive the session key using HKDF (same process as finalizeSession).
    const salt = await hashData(
      new Uint8Array([...this.nonce, ...this.peerNonce]).buffer
    );
    
    const ourEphPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ourEphPubArray = new Uint8Array(ourEphPubKey);
    const transcript = new Uint8Array([
      ...ourEphPubArray,
      ...this.nonce,
      ...new Uint8Array(this.peerEphemeral),
      ...this.peerNonce
    ]);
    // Use canonical ordering for info string (alphabetical) so both parties derive the same key.
    // For responder: peerId is the initiator, clientId is the responder
    // We need the same order as initiator uses: "E2EE-Prot v1" + initiatorId + responderId
    // Since peerId is the initiator and clientId is the responder, we use peerId + clientId
    // But initiator uses clientId (initiator) + peerId (responder), so we need to match that
    // Actually, let's use alphabetical order to ensure consistency
    const ids = [this.peerId, this.clientId].sort();
    const info = "E2EE-Prot v1" + ids[0] + ids[1];
    this.sessionKey = await deriveSessionKey(sharedSecret, salt, info);

    return this.sessionKey;
  }

  // Finalize the session after receiving the peer's response message.
  async finalizeSession(peerResponseMessage, peerPublicKeyJwk) {
    // Import the peer's public key.
    const peerPublicKey = await importPublicKey(peerPublicKeyJwk);

    // Convert base64 strings back to ArrayBuffers.
    const peerEphPubBuffer = base64ToArrayBuffer(peerResponseMessage.ephPub);
    const peerNonceBuffer = base64ToArrayBuffer(peerResponseMessage.nonce);
    const signatureBuffer = base64ToArrayBuffer(peerResponseMessage.signature);

    // Get our ephemeral public key.
    const ourEphPubKey = await window.crypto.subtle.exportKey("raw", this.ephemeral.publicKey);
    const ourEphPubArray = new Uint8Array(ourEphPubKey);

    // Reconstruct the exact message that was signed.
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

    // Verify the signature.
    const verify = await verifySignature(peerPublicKey, message.buffer, signatureBuffer);
    if (!verify) throw new Error("Invalid signature from peer");

    // Store the peer's ephemeral key and nonce.
    this.peerEphemeral = peerEphPubBuffer;
    this.peerNonce = new Uint8Array(peerNonceBuffer);

    // Import the peer's ephemeral public key so we can do ECDH.
    const peerEphPubKey = await importX25519PublicKey(peerEphPubBuffer);

    // Compute the shared secret using ECDH.
    const sharedSecret = await computeSharedSecret(this.ephemeral, peerEphPubKey);

    // Derive the session key using HKDF.
    // Use canonical ordering for salt (alphabetical by clientId) to ensure both parties use same salt.
    const saltOrder = this.clientId < this.peerId;
    const salt = await hashData(
      saltOrder
        ? new Uint8Array([...this.nonce, ...this.peerNonce]).buffer
        : new Uint8Array([...this.peerNonce, ...this.nonce]).buffer
    );
    const transcript = new Uint8Array([
      ...ourEphPubArray,
      ...this.nonce,
      ...new Uint8Array(peerEphPubBuffer),
      ...this.peerNonce
    ]);
    // Use canonical ordering (alphabetical) so both parties derive the same key.
    const ids = [this.clientId, this.peerId].sort();
    const info = "E2EE-Prot v1" + ids[0] + ids[1];
    this.sessionKey = await deriveSessionKey(sharedSecret, salt, info);

    return this.sessionKey;
  }

  // Create a key confirmation HMAC to prove we have the session key.
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

  // Verify a key confirmation HMAC from the peer.
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

  // Get the established session key, or null if not established yet.
  getSessionKey() {
    return this.sessionKey;
  }
}

// Export the module.
export { 
  KeyExchange,
  generateLongTermKeyPair,
  signData,
  verifySignature,
  exportPublicKey,
  importPublicKey
};
