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
