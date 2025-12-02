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

  // Validate inputs
  if (!ciphertext || !iv || !tag) {
    throw new Error("Missing required encryption data (ciphertext, iv, or tag)");
  }

  if (!sessionKey || !(sessionKey instanceof ArrayBuffer)) {
    throw new Error("Session key must be an ArrayBuffer");
  }

  // Convert base64 strings back to ArrayBuffers.
  let ciphertextBuffer, ivBuffer, tagBuffer;
  try {
    ciphertextBuffer = base64ToArrayBuffer(ciphertext);
    ivBuffer = base64ToArrayBuffer(iv);
    tagBuffer = base64ToArrayBuffer(tag);
  } catch (e) {
    throw new Error(`Failed to decode base64 data: ${e.message}`);
  }

  // Validate IV length (must be 12 bytes for GCM)
  if (ivBuffer.byteLength !== 12) {
    throw new Error(`Invalid IV length: expected 12 bytes, got ${ivBuffer.byteLength}`);
  }

  // Validate tag length (must be 16 bytes for GCM)
  if (tagBuffer.byteLength !== 16) {
    throw new Error(`Invalid tag length: expected 16 bytes, got ${tagBuffer.byteLength}`);
  }

  // Import the session key.
  let key;
  try {
    key = await window.crypto.subtle.importKey(
      "raw",
      sessionKey,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["decrypt"]
    );
  } catch (e) {
    throw new Error(`Failed to import session key: ${e.message}`);
  }

  // Combine ciphertext and tag for decryption.
  const combined = new Uint8Array(ciphertextBuffer.byteLength + tagBuffer.byteLength);
  combined.set(new Uint8Array(ciphertextBuffer), 0);
  combined.set(new Uint8Array(tagBuffer), ciphertextBuffer.byteLength);

  // Decrypt the message.
  let decrypted;
  try {
    decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBuffer,
        tagLength: 128 // 16 bytes = 128 bits
      },
      key,
      combined.buffer
    );
  } catch (e) {
    // OperationError typically means authentication failed (wrong key or corrupted data)
    throw new Error(`Decryption failed: ${e.message}. This usually means the session key doesn't match or the data is corrupted.`);
  }

  // Convert back to string.
  return new TextDecoder().decode(decrypted);
}

// Export the module.
export {
  encryptMessage,
  decryptMessage
};

