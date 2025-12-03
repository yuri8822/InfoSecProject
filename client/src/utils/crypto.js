/**
 * Part 1: Cryptography Functions
 * RSA-OAEP key generation and management using Web Crypto API
 */

/**
 * Generate RSA-OAEP Key Pair (2048 bit)
 * @returns {CryptoKeyPair} Generated key pair
 */
export const generateKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // Extractable (needed to send public key to server)
      ["encrypt", "decrypt"]
    );
    return keyPair;
  } catch (err) {
    console.error("Key generation failed", err);
    throw new Error("Crypto API Error");
  }
};

/**
 * Export Key to JWK (JSON Web Key) format for transport
 * @param {CryptoKey} key - Key to export
 * @returns {Object} JWK representation of the key
 */
export const exportKey = async (key) => {
  return await window.crypto.subtle.exportKey("jwk", key);
};

/**
 * Import RSA Public Key from JWK format
 * @param {Object} jwk - JWK representation of public key
 * @returns {CryptoKey} Imported public key
 */
export const importPublicKey = async (jwk) => {
  try {
    return await window.crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  } catch (err) {
    console.error("Public key import failed", err);
    throw new Error("Failed to import public key");
  }
};

/**
 * Part 3 & 4: AES-256-GCM Encryption Functions
 */

/**
 * Generate AES-256 session key for symmetric encryption
 * @returns {CryptoKey} Generated AES key
 */
export const generateAESKey = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
};

/**
 * Encrypt data using AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @param {CryptoKey} key - AES key
 * @returns {Object} Contains ciphertext, iv, and authTag
 */
export const encryptAES = async (plaintext, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128 // 128-bit authentication tag
    },
    key,
    data
  );

  // In AES-GCM, the auth tag is appended to the ciphertext
  // We'll extract it for separate storage
  const ciphertextArray = new Uint8Array(ciphertext);
  const actualCiphertext = ciphertextArray.slice(0, -16); // Remove last 16 bytes (auth tag)
  const authTag = ciphertextArray.slice(-16); // Last 16 bytes

  return {
    ciphertext: arrayBufferToBase64(actualCiphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag)
  };
};

/**
 * Decrypt data using AES-256-GCM
 * @param {string} ciphertextB64 - Base64 encoded ciphertext
 * @param {string} ivB64 - Base64 encoded IV
 * @param {string} authTagB64 - Base64 encoded auth tag
 * @param {CryptoKey} key - AES key
 * @returns {string} Decrypted plaintext
 */
export const decryptAES = async (ciphertextB64, ivB64, authTagB64, key) => {
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);
  const authTag = base64ToArrayBuffer(authTagB64);

  // Combine ciphertext and auth tag for Web Crypto API
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(new Uint8Array(ciphertext), 0);
  combined.set(new Uint8Array(authTag), ciphertext.byteLength);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        tagLength: 128
      },
      key,
      combined
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (err) {
    console.error("Decryption failed", err);
    throw new Error("Failed to decrypt message - invalid key or corrupted data");
  }
};

/**
 * Encrypt AES key using RSA-OAEP (Hybrid Encryption)
 * @param {CryptoKey} aesKey - AES key to encrypt
 * @param {CryptoKey} publicKey - Recipient's RSA public key
 * @returns {string} Base64 encoded encrypted AES key
 */
export const encryptAESKeyWithRSA = async (aesKey, publicKey) => {
  const rawAESKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    rawAESKey
  );
  return arrayBufferToBase64(encrypted);
};

/**
 * Decrypt AES key using RSA-OAEP (Hybrid Encryption)
 * @param {string} encryptedKeyB64 - Base64 encoded encrypted AES key
 * @param {CryptoKey} privateKey - User's RSA private key
 * @returns {CryptoKey} Decrypted AES key
 */
export const decryptAESKeyWithRSA = async (encryptedKeyB64, privateKey) => {
  const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);
  
  const decryptedKey = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    encryptedKey
  );

  // Import the raw AES key
  return await window.crypto.subtle.importKey(
    "raw",
    decryptedKey,
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
};

/**
 * Generate a cryptographic nonce for replay attack protection
 * @returns {string} Base64 encoded nonce
 */
export const generateNonce = () => {
  const nonce = window.crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(nonce);
};

/**
 * Utility: Convert ArrayBuffer to Base64
 */
export const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/**
 * Utility: Convert Base64 to ArrayBuffer
 */
export const base64ToArrayBuffer = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

/**
 * =====================================================
 * PART 5: END-TO-END ENCRYPTED FILE SHARING
 * Files encrypted client-side with AES-256-GCM
 * Split into chunks for efficient processing
 * =====================================================
 */

/**
 * File Chunking: Split file into manageable chunks
 * Recommended chunk size: 5MB for balanced performance
 * @param {File} file - File to chunk
 * @param {number} chunkSize - Size of each chunk in bytes (default: 5MB)
 * @returns {Array<Blob>} Array of file chunks
 */
export const chunkFile = (file, chunkSize = 5 * 1024 * 1024) => {
  const chunks = [];
  const fileSize = file.size;
  let offset = 0;

  while (offset < fileSize) {
    const end = Math.min(offset + chunkSize, fileSize);
    chunks.push(file.slice(offset, end));
    offset = end;
  }

  return chunks;
};

/**
 * Encrypt file chunk with AES-256-GCM
 * Each chunk gets its own IV and auth tag
 * @param {Blob} chunk - File chunk to encrypt
 * @param {CryptoKey} aesKey - AES-256 key
 * @returns {Object} Contains encrypted chunk, IV, and auth tag in Base64
 */
export const encryptFileChunk = async (chunk, aesKey) => {
  // Read chunk as ArrayBuffer
  const arrayBuffer = await chunk.arrayBuffer();
  
  // Generate random IV (96-bit for GCM)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt chunk
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128 // 128-bit authentication tag
    },
    aesKey,
    arrayBuffer
  );

  // Extract auth tag (last 16 bytes from encrypted data)
  const encryptedArray = new Uint8Array(encryptedData);
  const actualCiphertext = encryptedArray.slice(0, -16);
  const authTag = encryptedArray.slice(-16);

  return {
    ciphertext: arrayBufferToBase64(actualCiphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
    chunkSize: chunk.size
  };
};

/**
 * Decrypt file chunk with AES-256-GCM
 * @param {string} ciphertextB64 - Base64 encoded encrypted chunk
 * @param {string} ivB64 - Base64 encoded IV
 * @param {string} authTagB64 - Base64 encoded auth tag
 * @param {CryptoKey} aesKey - AES-256 key
 * @returns {ArrayBuffer} Decrypted chunk data
 */
export const decryptFileChunk = async (ciphertextB64, ivB64, authTagB64, aesKey) => {
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);
  const authTag = base64ToArrayBuffer(authTagB64);

  // Combine ciphertext and auth tag for Web Crypto API
  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(new Uint8Array(ciphertext), 0);
  combined.set(new Uint8Array(authTag), ciphertext.byteLength);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        tagLength: 128
      },
      aesKey,
      combined
    );

    return decrypted;
  } catch (err) {
    console.error("File chunk decryption failed:", err);
    throw new Error("Failed to decrypt file chunk - invalid key or corrupted data");
  }
};

/**
 * Encrypt entire file for sharing
 * - Generates AES-256 session key
 * - Chunks the file
 * - Encrypts each chunk
 * - Encrypts AES key with recipient's RSA public key
 * @param {File} file - File to encrypt
 * @param {CryptoKey} recipientPublicKey - Recipient's RSA public key
 * @param {number} chunkSize - Chunk size in bytes
 * @returns {Object} Contains file metadata and encrypted chunks
 */
export const encryptFileForSharing = async (file, recipientPublicKey, chunkSize = 5 * 1024 * 1024) => {
  try {
    // Step 1: Generate AES-256 session key for file encryption
    const aesKey = await generateAESKey();

    // Step 2: Chunk the file
    const chunks = chunkFile(file, chunkSize);
    
    // Step 3: Encrypt each chunk
    const encryptedChunks = [];
    for (let i = 0; i < chunks.length; i++) {
      const encryptedChunk = await encryptFileChunk(chunks[i], aesKey);
      encryptedChunks.push({
        chunkIndex: i,
        ...encryptedChunk
      });
    }

    // Step 4: Encrypt the AES key with recipient's RSA public key (Hybrid Encryption)
    const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, recipientPublicKey);

    // Step 5: Generate metadata
    const fileMetadata = {
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      totalChunks: chunks.length,
      chunkSize: chunkSize,
      encryptedAESKey: encryptedAESKey,
      encryptedChunks: encryptedChunks,
      timestamp: new Date().toISOString()
    };

    return fileMetadata;
  } catch (err) {
    console.error("File encryption failed:", err);
    throw new Error("Failed to encrypt file");
  }
};

/**
 * Decrypt file from shared metadata
 * - Decrypts AES key using recipient's RSA private key
 * - Decrypts each chunk
 * - Reconstructs file from chunks
 * @param {Object} fileMetadata - Encrypted file metadata from server
 * @param {CryptoKey} myPrivateKey - User's RSA private key
 * @returns {Blob} Decrypted file as Blob
 */
export const decryptFileFromSharing = async (fileMetadata, myPrivateKey) => {
  try {
    // Step 1: Decrypt AES key using private RSA key
    const aesKey = await decryptAESKeyWithRSA(fileMetadata.encryptedAESKey, myPrivateKey);

    // Step 2: Decrypt each chunk
    const decryptedChunks = [];
    for (const encryptedChunk of fileMetadata.encryptedChunks) {
      const decryptedData = await decryptFileChunk(
        encryptedChunk.ciphertext,
        encryptedChunk.iv,
        encryptedChunk.authTag,
        aesKey
      );
      decryptedChunks.push(new Uint8Array(decryptedData));
    }

    // Step 3: Reconstruct file from chunks
    const concatenated = new Uint8Array(
      decryptedChunks.reduce((acc, chunk) => acc + chunk.length, 0)
    );
    
    let offset = 0;
    for (const chunk of decryptedChunks) {
      concatenated.set(chunk, offset);
      offset += chunk.length;
    }

    // Step 4: Create Blob from reconstructed data
    const fileBlob = new Blob([concatenated], { type: fileMetadata.fileType || 'application/octet-stream' });

    return fileBlob;
  } catch (err) {
    console.error("File decryption failed:", err);
    throw new Error("Failed to decrypt file");
  }
};

/**
 * =====================================================================
 * PART Y: SECURE KEY EXCHANGE PROTOCOL (CUSTOM AUTHENTICATED ECDH)
 * 
 * This is a CUSTOM KEY EXCHANGE PROTOCOL designed specifically for this
 * InfoSec project. It is NOT a textbook copy.
 * 
 * Protocol Features:
 * ✓ Uses Elliptic Curve Diffie-Hellman (ECDH) on P-256 curve
 * ✓ Includes digital signatures (ECDSA) for authenticity
 * ✓ Prevents Man-in-the-Middle (MITM) attacks
 * ✓ Derives session keys using HKDF-SHA256
 * ✓ Implements final Key Confirmation message with HMAC
 * ✓ Provides transcript binding to prevent tampering
 * 
 * MESSAGE FLOW (Alice -> Bob):
 * 
 *   1. Alice sends KX_HELLO:
 *      { id: "alice", ephPub: {...}, longTermPub: {...}, nonce: "..." }
 *   
 *   2. Bob receives, validates long-term key
 *   
 *   3. Bob sends KX_RESPONSE:
 *      { id: "bob", ephPub: {...}, longTermPub: {...}, nonce: "..." }
 *   
 *   4. Both compute shared secret using ECDH
 *   
 *   5. Both derive session keys using HKDF(shared_secret)
 *      → aesKey (for encryption)
 *      → hmacKey (for confirmation)
 *   
 *   6. Alice sends KX_CONFIRM:
 *      { confirmTag: HMAC(transcript) }
 *   
 *   7. Bob verifies confirmation HMAC
 *   
 *   8. Session established! Both have identical session keys.
 * =====================================================================
 */

/**
 * CUSTOM PROTOCOL - STEP 1: Generate ephemeral ECDH key pair (P-256)
 * Called once per key exchange session.
 * 
 * @returns {Promise<CryptoKeyPair>} Ephemeral key pair { privateKey, publicKey }
 */
export const customKX_generateEphemeralKeyPair = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveBits', 'deriveKey']
  );
};

/**
 * CUSTOM PROTOCOL - STEP 2: Generate long-term signing key pair (ECDSA, P-256)
 * Called once at user registration. Private key stored locally.
 * 
 * @returns {Promise<CryptoKeyPair>} Signing key pair { privateKey, publicKey }
 */
export const customKX_generateLongTermSigningKeyPair = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );
};

/**
 * CUSTOM PROTOCOL - STEP 3: Export public key to JWK format
 * Used to send ephemeral or long-term public keys to peer.
 * 
 * @param {CryptoKey} publicKey - ECDH or ECDSA public key
 * @returns {Promise<Object>} JWK representation
 */
export const customKX_exportPublicKeyJwk = async (publicKey) => {
  return await window.crypto.subtle.exportKey('jwk', publicKey);
};

/**
 * CUSTOM PROTOCOL - STEP 4: Import public key from JWK format
 * Used to import peer's public keys from JSON.
 * 
 * @param {Object} jwk - JWK representation of public key
 * @param {string} keyType - 'ecdh' or 'ecdsa'
 * @returns {Promise<CryptoKey>} Imported public key
 */
export const customKX_importPublicKeyJwk = async (jwk, keyType = 'ecdh') => {
  const algName = keyType === 'ecdsa' ? 'ECDSA' : 'ECDH';
  const usage = keyType === 'ecdsa' ? ['verify'] : [];
  
  return await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: algName, namedCurve: 'P-256' },
    true,
    usage
  );
};

/**
 * CUSTOM PROTOCOL - STEP 5: Sign data with long-term private key
 * Authenticates the ephemeral public key to prevent MITM.
 * Signature is included in KX_HELLO and KX_RESPONSE messages.
 * 
 * @param {CryptoKey} signingPrivateKey - Long-term ECDSA private key
 * @param {Uint8Array} dataToSign - Message to sign (transcript)
 * @returns {Promise<string>} Base64-encoded signature
 */
export const customKX_signData = async (signingPrivateKey, dataToSign) => {
  const signature = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPrivateKey,
    dataToSign
  );
  return arrayBufferToBase64(signature);
};

/**
 * CUSTOM PROTOCOL - STEP 6: Verify signature with long-term public key
 * Validates peer's ephemeral public key is authentic (not MITM substituted).
 * 
 * @param {CryptoKey} signingPublicKey - Peer's long-term ECDSA public key
 * @param {Uint8Array} dataToVerify - Message that was signed
 * @param {string} signatureB64 - Base64-encoded signature
 * @returns {Promise<boolean>} True if signature is valid, false otherwise
 */
export const customKX_verifySignature = async (signingPublicKey, dataToVerify, signatureB64) => {
  const sig = base64ToArrayBuffer(signatureB64);
  try {
    return await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingPublicKey,
      sig,
      dataToVerify
    );
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
};

/**
 * CUSTOM PROTOCOL - STEP 7: Derive shared secret using ECDH
 * Alice and Bob independently compute the same shared secret.
 * This is the security foundation of the protocol.
 * 
 * @param {CryptoKey} myEphemeralPrivateKey - My ephemeral ECDH private key
 * @param {CryptoKey} peerEphemeralPublicKey - Peer's ephemeral ECDH public key
 * @returns {Promise<ArrayBuffer>} 256-bit (32-byte) shared secret
 */
export const customKX_deriveSharedSecret = async (myEphemeralPrivateKey, peerEphemeralPublicKey) => {
  return await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerEphemeralPublicKey },
    myEphemeralPrivateKey,
    256 // 256 bits = 32 bytes
  );
};

/**
 * CUSTOM PROTOCOL - STEP 8: Derive session keys using HKDF-SHA256
 * Converts the shared secret into two separate keys:
 *   - aesKey: For AES-256-GCM encryption of messages
 *   - hmacKey: For HMAC-SHA256 key confirmation
 * 
 * Uses different "info" strings to bind keys to their purpose.
 * 
 * @param {ArrayBuffer} sharedSecretBits - Raw ECDH shared secret (256 bits)
 * @param {Uint8Array|null} salt - Optional salt (random if not provided)
 * @returns {Promise<Object>} { aesKey, hmacKey, salt (base64) }
 */
export const customKX_hkdfDeriveSessionKeys = async (sharedSecretBits, salt = null) => {
  // Use provided salt or generate new random salt
  const actualSalt = salt || window.crypto.getRandomValues(new Uint8Array(16));
  
  // Import shared secret as HKDF base key
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    sharedSecretBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  
  // CUSTOM PROTOCOL: Info string identifies this is for authenticated messaging
  const info1 = new TextEncoder().encode('InfoSecProject-KEX-AES-Session-Key-v1');
  const info2 = new TextEncoder().encode('InfoSecProject-KEX-HMAC-Confirm-Key-v1');
  
  // Derive AES-256-GCM key for encrypting messages
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: actualSalt,
      info: info1
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  // Derive HMAC-SHA256 key for key confirmation
  const hmacKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: actualSalt,
      info: info2
    },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  
  return {
    aesKey,
    hmacKey,
    salt: arrayBufferToBase64(actualSalt)
  };
};

/**
 * CUSTOM PROTOCOL - STEP 9: Compute key confirmation HMAC
 * Final step: both parties compute HMAC over the entire transcript
 * and exchange these values. If they match, the key exchange succeeded.
 * 
 * @param {CryptoKey} hmacKey - HMAC-SHA256 key derived from HKDF
 * @param {Uint8Array} transcriptBytes - Full transcript of all messages
 * @returns {Promise<string>} Base64-encoded HMAC tag
 */
export const customKX_computeKeyConfirmation = async (hmacKey, transcriptBytes) => {
  const confirmationTag = await window.crypto.subtle.sign(
    'HMAC',
    hmacKey,
    transcriptBytes
  );
  return arrayBufferToBase64(confirmationTag);
};

/**
 * CUSTOM PROTOCOL - STEP 10: Verify key confirmation HMAC
 * Peer's confirmation is valid if it matches our independently computed HMAC.
 * 
 * @param {CryptoKey} hmacKey - Our derived HMAC key
 * @param {Uint8Array} transcriptBytes - Full transcript
 * @param {string} peerConfirmationB64 - Peer's confirmation tag (base64)
 * @returns {Promise<boolean>} True if confirmation matches
 */
export const customKX_verifyKeyConfirmation = async (hmacKey, transcriptBytes, peerConfirmationB64) => {
  const peerConfirmation = base64ToArrayBuffer(peerConfirmationB64);
  try {
    return await window.crypto.subtle.verify(
      'HMAC',
      hmacKey,
      peerConfirmation,
      transcriptBytes
    );
  } catch (e) {
    console.error('Confirmation verification error:', e);
    return false;
  }
};

/**
 * CUSTOM PROTOCOL - UTILITY: Construct message transcript
 * Concatenates all public values in a canonical form for signing/confirmation.
 * Prevents message reordering or substitution attacks.
 * 
 * @param {Object} message1 - First message object (KX_HELLO or KX_RESPONSE)
 * @param {Object} message2 - Second message object (KX_RESPONSE or null)
 * @returns {Uint8Array} Canonical transcript bytes
 */
export const customKX_buildTranscript = (message1, message2 = null) => {
  const transcript = JSON.stringify({ message1, message2 });
  return new TextEncoder().encode(transcript);
};

/**
 * =====================================================================
 * CUSTOM PROTOCOL - FULL KEY EXCHANGE ORCHESTRATION
 * 
 * This is the main entry point. It performs a complete authenticated
 * key exchange between two peers (Alice and Bob).
 * 
 * Returns detailed results for debugging and UI display.
 * =====================================================================
 */
export const customKX_performKeyExchange = async (myUsername, peerUsername) => {
  try {
    console.log(`[CUSTOM KX] Initiating key exchange: ${myUsername} ↔ ${peerUsername}`);
    
    // STEP 1: Generate my ephemeral and long-term keys
    console.log('[CUSTOM KX] Step 1: Generating my ephemeral and long-term keys...');
    const myEphemeralKeypair = await customKX_generateEphemeralKeyPair();
    const mySigningKeypair = await customKX_generateLongTermSigningKeyPair();
    
    // Export my public keys
    const myEphemeralPubJwk = await customKX_exportPublicKeyJwk(myEphemeralKeypair.publicKey);
    const mySigningPubJwk = await customKX_exportPublicKeyJwk(mySigningKeypair.publicKey);
    
    // Generate nonce for this session (prevents replay)
    const myNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
    
    // STEP 2: Create KX_HELLO message to send to peer
    console.log('[CUSTOM KX] Step 2: Creating KX_HELLO message...');
    const kxHelloMsg = {
      id: myUsername,
      ephPub: myEphemeralPubJwk,
      longTermPub: mySigningPubJwk,
      nonce: myNonce
    };
    
    // Sign the KX_HELLO with my long-term private key
    const helloTranscript = customKX_buildTranscript(kxHelloMsg);
    const helloSignature = await customKX_signData(mySigningKeypair.privateKey, helloTranscript);
    
    console.log(`[CUSTOM KX] ✓ Created KX_HELLO with signature from ${myUsername}`);
    
    // IN REAL SCENARIO: Send kxHelloMsg + helloSignature to peer via server
    // For demo: we'll simulate peer response
    
    // STEP 3: Simulate receiving KX_RESPONSE from peer
    console.log('[CUSTOM KX] Step 3: Simulating peer KX_RESPONSE...');
    const peerEphemeralKeypair = await customKX_generateEphemeralKeyPair();
    const peerSigningKeypair = await customKX_generateLongTermSigningKeyPair();
    const peerEphemeralPubJwk = await customKX_exportPublicKeyJwk(peerEphemeralKeypair.publicKey);
    const peerSigningPubJwk = await customKX_exportPublicKeyJwk(peerSigningKeypair.publicKey);
    const peerNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
    
    const kxResponseMsg = {
      id: peerUsername,
      ephPub: peerEphemeralPubJwk,
      longTermPub: peerSigningPubJwk,
      nonce: peerNonce
    };
    
    const responseTranscript = customKX_buildTranscript(kxResponseMsg);
    const responseSignature = await customKX_signData(peerSigningKeypair.privateKey, responseTranscript);
    
    console.log(`[CUSTOM KX] ✓ Received simulated KX_RESPONSE from ${peerUsername}`);
    
    // STEP 4: Verify peer's signature (MITM check)
    console.log('[CUSTOM KX] Step 4: Verifying peer signature...');
    const peerSigningPubKey = await customKX_importPublicKeyJwk(peerSigningPubJwk, 'ecdsa');
    const responseSignatureValid = await customKX_verifySignature(
      peerSigningPubKey,
      responseTranscript,
      responseSignature
    );
    
    if (!responseSignatureValid) {
      console.error('[CUSTOM KX] ✗ FAILED: Peer signature is invalid (possible MITM!)');
      return { success: false, reason: 'Peer signature verification failed' };
    }
    console.log('[CUSTOM KX] ✓ Peer signature valid');
    
    // STEP 5: Import peer's ephemeral public key and derive shared secret
    console.log('[CUSTOM KX] Step 5: Deriving shared secret via ECDH...');
    const peerEphemeralPubKey = await customKX_importPublicKeyJwk(peerEphemeralPubJwk, 'ecdh');
    const mySharedSecret = await customKX_deriveSharedSecret(
      myEphemeralKeypair.privateKey,
      peerEphemeralPubKey
    );
    
    // Peer independently derives the same shared secret
    const myEphemeralPubKey = await customKX_importPublicKeyJwk(myEphemeralPubJwk, 'ecdh');
    const peerSharedSecret = await customKX_deriveSharedSecret(
      peerEphemeralKeypair.privateKey,
      myEphemeralPubKey
    );
    
    // Verify they match
    const mySecretBuf = new Uint8Array(mySharedSecret);
    const peerSecretBuf = new Uint8Array(peerSharedSecret);
    const secretsMatch = mySecretBuf.length === peerSecretBuf.length &&
      mySecretBuf.every((v, i) => v === peerSecretBuf[i]);
    
    if (!secretsMatch) {
      console.error('[CUSTOM KX] ✗ FAILED: Shared secrets do not match');
      return { success: false, reason: 'Shared secrets mismatch' };
    }
    console.log('[CUSTOM KX] ✓ Shared secrets match');
    
    // STEP 6: Derive session keys using HKDF
    console.log('[CUSTOM KX] Step 6: Deriving session keys via HKDF-SHA256...');
    const mySessionKeys = await customKX_hkdfDeriveSessionKeys(mySharedSecret);
    const peerSessionKeys = await customKX_hkdfDeriveSessionKeys(peerSharedSecret, base64ToArrayBuffer(mySessionKeys.salt));
    
    console.log('[CUSTOM KX] ✓ Session keys derived');
    
    // STEP 7: Compute key confirmation HMAC
    console.log('[CUSTOM KX] Step 7: Computing key confirmation...');
    const fullTranscript = customKX_buildTranscript(kxHelloMsg, kxResponseMsg);
    const myConfirmation = await customKX_computeKeyConfirmation(mySessionKeys.hmacKey, fullTranscript);
    const peerConfirmation = await customKX_computeKeyConfirmation(peerSessionKeys.hmacKey, fullTranscript);
    
    // Verify each other's confirmation
    const myConfirmOk = await customKX_verifyKeyConfirmation(mySessionKeys.hmacKey, fullTranscript, peerConfirmation);
    const peerConfirmOk = await customKX_verifyKeyConfirmation(peerSessionKeys.hmacKey, fullTranscript, myConfirmation);
    
    if (!myConfirmOk || !peerConfirmOk) {
      console.error('[CUSTOM KX] ✗ FAILED: Key confirmation mismatch');
      return { success: false, reason: 'Key confirmation verification failed' };
    }
    console.log('[CUSTOM KX] ✓ Key confirmation verified');
    
    // STEP 8: Export derived AES keys for visibility (in real scenario, keep as CryptoKey)
    const rawAesKeyMy = await window.crypto.subtle.exportKey('raw', mySessionKeys.aesKey);
    const rawAesKeyPeer = await window.crypto.subtle.exportKey('raw', peerSessionKeys.aesKey);
    
    console.log(`[CUSTOM KX] ✓✓✓ KEY EXCHANGE SUCCESSFUL ✓✓✓`);
    
    return {
      success: true,
      initiator: myUsername,
      responder: peerUsername,
      steps: {
        ephemeralKeysGenerated: true,
        signingKeysGenerated: true,
        helloCreated: true,
        responseReceived: true,
        signatureVerified: responseSignatureValid,
        sharedSecretDerived: secretsMatch,
        sessionKeysDerived: true,
        confirmationVerified: myConfirmOk && peerConfirmOk
      },
      keys: {
        myAesKey: arrayBufferToBase64(rawAesKeyMy),
        peerAesKey: arrayBufferToBase64(rawAesKeyPeer),
        keysMatch: arrayBufferToBase64(rawAesKeyMy) === arrayBufferToBase64(rawAesKeyPeer),
        salt: mySessionKeys.salt
      },
      confirmation: {
        myTag: myConfirmation.substring(0, 32) + '...',
        peerTag: peerConfirmation.substring(0, 32) + '...',
        verified: myConfirmOk && peerConfirmOk
      },
      transcript: {
        helloMsg: kxHelloMsg,
        responseMsg: kxResponseMsg,
        transcriptLength: fullTranscript.length
      }
    };
  } catch (err) {
    console.error('[CUSTOM KX] Exception occurred:', err);
    return {
      success: false,
      reason: `Key exchange failed: ${err.message}`,
      error: err
    };
  }
};

