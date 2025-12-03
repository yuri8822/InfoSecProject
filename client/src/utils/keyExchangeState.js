/**
 * Key Exchange State Management
 * Stores ephemeral keys and session state in memory (never persisted)
 */


const activeSessions = new Map();

const establishedSessionKeys = new Map();

export const generateSessionId = () => {
    return `kx_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
};

export const storeActiveSession = (sessionId, sessionData) => {
    activeSessions.set(sessionId, {
        ...sessionData,
        createdAt: Date.now()
    });
    
    setTimeout(() => {
        activeSessions.delete(sessionId);
    }, 10 * 60 * 1000);
};

export const getActiveSession = (sessionId) => {
    return activeSessions.get(sessionId);
};

export const removeActiveSession = (sessionId) => {
    activeSessions.delete(sessionId);
};

export const storeEstablishedSessionKeys = (myUsername, peerUsername, aesKey, hmacKey) => {
    const key = [myUsername, peerUsername].sort().join('-');
    establishedSessionKeys.set(key, {
        aesKey,
        hmacKey,
        establishedAt: Date.now()
    });
};

export const getEstablishedSessionKeys = (myUsername, peerUsername) => {
    const key = [myUsername, peerUsername].sort().join('-');
    return establishedSessionKeys.get(key);
};

export const clearAllSessions = () => {
    activeSessions.clear();
    establishedSessionKeys.clear();
};

