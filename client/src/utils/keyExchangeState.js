/**
 * Key Exchange State Management
 * Stores ephemeral keys and session state in memory (never persisted)
 */

// In-memory storage for active key exchange sessions
// Key: sessionId, Value: { ephemeralPrivateKey, signingPrivateKey, status, ... }
const activeSessions = new Map();

// In-memory storage for established session keys
// Key: "username1-username2", Value: { aesKey: CryptoKey, hmacKey: CryptoKey, establishedAt }
const establishedSessionKeys = new Map();

/**
 * Generate unique session ID
 */
export const generateSessionId = () => {
    return `kx_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
};

/**
 * Store active key exchange session
 * @param {string} sessionId
 * @param {Object} sessionData - { ephemeralPrivateKey, signingPrivateKey, role, peerUsername, ... }
 */
export const storeActiveSession = (sessionId, sessionData) => {
    activeSessions.set(sessionId, {
        ...sessionData,
        createdAt: Date.now()
    });
    
    // Auto-cleanup after 10 minutes
    setTimeout(() => {
        activeSessions.delete(sessionId);
    }, 10 * 60 * 1000);
};

/**
 * Get active session
 */
export const getActiveSession = (sessionId) => {
    return activeSessions.get(sessionId);
};

/**
 * Remove active session (after completion or failure)
 */
export const removeActiveSession = (sessionId) => {
    activeSessions.delete(sessionId);
};

/**
 * Store established session keys for a user pair
 * @param {string} myUsername
 * @param {string} peerUsername
 * @param {CryptoKey} aesKey
 * @param {CryptoKey} hmacKey
 */
export const storeEstablishedSessionKeys = (myUsername, peerUsername, aesKey, hmacKey) => {
    // Normalize usernames (alphabetical order for consistency)
    const key = [myUsername, peerUsername].sort().join('-');
    establishedSessionKeys.set(key, {
        aesKey,
        hmacKey,
        establishedAt: Date.now()
    });
};

/**
 * Get established session keys for a user pair
 */
export const getEstablishedSessionKeys = (myUsername, peerUsername) => {
    const key = [myUsername, peerUsername].sort().join('-');
    return establishedSessionKeys.get(key);
};

/**
 * Clear all sessions (on logout)
 */
export const clearAllSessions = () => {
    activeSessions.clear();
    establishedSessionKeys.clear();
};

