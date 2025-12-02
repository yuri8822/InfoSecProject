/**
 * Part 8: Key Storage using IndexedDB
 * Secure client-side storage for private keys
 */

const DB_NAME = "SecureMsgDB";
const STORE_NAME = "key_store";

/**
 * Open IndexedDB connection
 */
export const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onerror = (event) => reject(new Error(`Error opening DB: ${event.target.error}`));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
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
