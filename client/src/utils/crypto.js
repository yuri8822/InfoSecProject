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
