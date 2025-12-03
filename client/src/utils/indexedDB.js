/**
 * Part 8: Key Storage using IndexedDB
 * Secure client-side storage for private keys
 */

const DB_NAME = "SecureMsgDB";
const STORE_NAME = "key_store";
const SIGNING_STORE_NAME = "signing_key_store";

/**
 * Open IndexedDB connection
 */
export const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 3); // Increment version for new store
    request.onerror = (event) => reject(new Error(`Error opening DB: ${event.target.error}`));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
      }
      if (!db.objectStoreNames.contains(SIGNING_STORE_NAME)) {
        db.createObjectStore(SIGNING_STORE_NAME, { keyPath: "userId" });
      }
    };
  });
};

/**
 * Store private key in IndexedDB
 * @param {string} userId - User identifier
 * @param {CryptoKey} privateKey - Private key to store
 */
export const storePrivateKey = async (userId, privateKey) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put({ userId, key: privateKey });
    request.onsuccess = () => resolve();
    request.onerror = () => reject("Error storing key");
  });
};

/**
 * Retrieve private key from IndexedDB
 * @param {string} userId - User identifier
 * @returns {CryptoKey|null} Private key or null if not found
 */
export const getPrivateKey = async (userId) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(userId);
    request.onsuccess = () => resolve(request.result ? request.result.key : null);
    request.onerror = () => reject("Error retrieving key");
  });
};

/**
 * Store ECDSA signing private key
 * @param {string} userId - User identifier
 * @param {CryptoKey} signingPrivateKey - ECDSA signing private key to store
 */
export const storeSigningPrivateKey = async (userId, signingPrivateKey) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SIGNING_STORE_NAME, "readwrite");
    const store = tx.objectStore(SIGNING_STORE_NAME);
    
    // Export key to JWK for storage
    window.crypto.subtle.exportKey('jwk', signingPrivateKey).then((jwk) => {
      const request = store.put({ 
        userId, 
        keyData: jwk,
        keyType: 'ecdsa_signing',
        createdAt: new Date()
      });
      request.onsuccess = () => resolve();
      request.onerror = () => reject("Error storing signing key");
    }).catch((err) => reject(`Error exporting signing key: ${err.message}`));
  });
};

/**
 * Get ECDSA signing private key
 * @param {string} userId - User identifier
 * @returns {CryptoKey|null} Signing private key or null if not found
 */
export const getSigningPrivateKey = async (userId) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(SIGNING_STORE_NAME, "readonly");
    const store = tx.objectStore(SIGNING_STORE_NAME);
    const request = store.get(userId);
    request.onsuccess = async () => {
      if (!request.result) {
        resolve(null);
        return;
      }
      
      try {
        // Import key from JWK
        const key = await window.crypto.subtle.importKey(
          'jwk',
          request.result.keyData,
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['sign']
        );
        resolve(key);
      } catch (err) {
        reject(`Error importing signing key: ${err.message}`);
      }
    };
    request.onerror = () => reject("Error retrieving signing key");
  });
};
