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
