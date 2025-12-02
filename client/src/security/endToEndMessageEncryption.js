// [4] endToEndMessageEncryption.js - AES-256-GCM encryption for messages

// Convert ArrayBuffer to base64 string.
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

// Encrypt a message using AES-256-GCM.
// Returns: { ciphertext (base64), iv (base64), tag (base64) }
async function encryptMessage(plaintext, sessionKey) {
  // Generate a fresh random IV (12 bytes for GCM).
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);

  // Import the session key for AES-GCM.
  const key = await window.crypto.subtle.importKey(
    "raw",
    sessionKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt"]
  );

  // Convert plaintext to ArrayBuffer.
  const plaintextBuffer = new TextEncoder().encode(plaintext);

  // Encrypt the message.
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    plaintextBuffer
  );

  // Extract the ciphertext and authentication tag.
  // GCM appends the tag (16 bytes) to the end of the ciphertext.
  const tagLength = 16;
  const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
  const tag = encrypted.slice(encrypted.byteLength - tagLength);

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
    tag: arrayBufferToBase64(tag)
  };
}

// Decrypt a message using AES-256-GCM.
// Returns: plaintext string
async function decryptMessage(encryptedData, sessionKey) {
  const { ciphertext, iv, tag } = encryptedData;

  // Convert base64 strings back to ArrayBuffers.
  const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
  const ivBuffer = base64ToArrayBuffer(iv);
  const tagBuffer = base64ToArrayBuffer(tag);

  // Import the session key.
  const key = await window.crypto.subtle.importKey(
    "raw",
    sessionKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["decrypt"]
  );

  // Combine ciphertext and tag for decryption.
  const combined = new Uint8Array(ciphertextBuffer.byteLength + tagBuffer.byteLength);
  combined.set(new Uint8Array(ciphertextBuffer), 0);
  combined.set(new Uint8Array(tagBuffer), ciphertextBuffer.byteLength);

  // Decrypt the message.
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivBuffer
    },
    key,
    combined.buffer
  );

  // Convert back to string.
  return new TextDecoder().decode(decrypted);
}

// Export the module.
export {
  encryptMessage,
  decryptMessage
};

