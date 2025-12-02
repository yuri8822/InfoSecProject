/**
 * Part 2: Authentication & API Communication
 * All API calls and security event logging
 */

import { API_URL } from './config';

/**
 * Log security event to server
 * @param {string} type - Event type
 * @param {string} details - Event details
 * @param {string|null} token - Optional JWT token
 */
export const logSecurityEvent = async (type, details, token = null) => {
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    await fetch(`${API_URL}/log`, {
      method: "POST",
      headers,
      body: JSON.stringify({ type, details, level: 'info' })
    });
  } catch (err) {
    console.error("Failed to push log to server", err);
  }
};

/**
 * Register new user with public key
 * @param {string} username - Username
 * @param {string} password - Password
 * @param {Object} publicKey - Public key in JWK format
 * @returns {Object} Response data
 */
export const registerUser = async (username, password, publicKey) => {
  const res = await fetch(`${API_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, publicKey })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Registration failed');
  
  return data;
};

/**
 * Login user
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Object} Response data with token
 */
export const loginUser = async (username, password) => {
  const res = await fetch(`${API_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Login failed');
  
  return data;
};

/**
 * Fetch security audit logs
 * @param {string} token - JWT token
 * @returns {Array} List of logs
 */
export const fetchLogs = async (token) => {
  const res = await fetch(`${API_URL}/logs`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch logs');
  return data;
};

/**
 * Fetch all registered users
 * @param {string} token - JWT token
 * @returns {Array} List of users
 */
export const fetchUsers = async (token) => {
  const res = await fetch(`${API_URL}/users`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch users');
  return data;
};

/**
 * Fetch specific user's public key
 * @param {string} username - Target username
 * @param {string} token - JWT token
 * @returns {Object|null} Public key in JWK format
 */
export const fetchUserPublicKey = async (username, token) => {
  try {
    const res = await fetch(`${API_URL}/users/${username}/public-key`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) return data.publicKey;
    return null;
  } catch (err) {
    console.error("Fetch public key failed", err);
    return null;
  }
};

/**
 * Part 4: Send encrypted message
 * @param {Object} messageData - Message data with encryption fields
 * @param {string} token - JWT token
 * @returns {Object} Response data
 */
export const sendMessage = async (messageData, token) => {
  const res = await fetch(`${API_URL}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify(messageData)
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Failed to send message');
  
  return data;
};

/**
 * Fetch messages with another user
 * @param {string} otherUsername - Other user's username
 * @param {string} token - JWT token
 * @returns {Array} List of messages
 */
export const fetchMessages = async (otherUsername, token) => {
  const res = await fetch(`${API_URL}/messages/${otherUsername}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch messages');
  return data;
};

/**
 * =====================================================
 * PART 5: END-TO-END ENCRYPTED FILE SHARING API
 * Upload encrypted files, download, and manage shares
 * =====================================================
 */

/**
 * Upload encrypted file to server
 * File is already encrypted client-side before upload
 * @param {Object} fileMetadata - Encrypted file metadata and chunks
 * @param {string} recipientUsername - Username of recipient
 * @param {string} token - JWT token
 * @returns {Object} Server response with file ID
 */
export const uploadEncryptedFile = async (fileMetadata, recipientUsername, token) => {
  try {
    const res = await fetch(`${API_URL}/files/upload`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        ...fileMetadata,
        recipientUsername
      })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File upload failed');
    
    console.log(`[FILE_SHARING] File uploaded successfully. ID: ${data.fileId}`);
    return data;
  } catch (err) {
    console.error("File upload failed:", err);
    throw new Error("Failed to upload encrypted file");
  }
};

/**
 * Fetch list of files shared with current user
 * Returns encrypted metadata - decryption happens client-side
 * @param {string} token - JWT token
 * @returns {Array} List of shared files
 */
export const fetchSharedFiles = async (token) => {
  try {
    const res = await fetch(`${API_URL}/files`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch shared files');
    
    console.log(`[FILE_SHARING] Retrieved ${data.length || 0} shared files`);
    return data;
  } catch (err) {
    console.error("Fetch shared files failed:", err);
    throw new Error("Failed to fetch shared files");
  }
};

/**
 * Download encrypted file from server
 * Returns encrypted metadata that client decrypts
 * @param {string} fileId - File ID on server
 * @param {string} token - JWT token
 * @returns {Object} Encrypted file metadata
 */
export const downloadEncryptedFile = async (fileId, token) => {
  try {
    const res = await fetch(`${API_URL}/files/download/${fileId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File download failed');
    
    console.log(`[FILE_SHARING] Downloaded encrypted file: ${fileId}`);
    return data;
  } catch (err) {
    console.error("File download failed:", err);
    throw new Error("Failed to download encrypted file");
  }
};

/**
 * Delete shared file (sender only)
 * @param {string} fileId - File ID to delete
 * @param {string} token - JWT token
 * @returns {Object} Server response
 */
export const deleteSharedFile = async (fileId, token) => {
  try {
    const res = await fetch(`${API_URL}/files/${fileId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File deletion failed');
    
    console.log(`[FILE_SHARING] File deleted: ${fileId}`);
    return data;
  } catch (err) {
    console.error("File deletion failed:", err);
    throw new Error("Failed to delete file");
  }
};

/**
 * Log file sharing event for security audit
 * @param {string} eventType - Type of event (e.g., 'FILE_UPLOAD', 'FILE_DOWNLOAD', 'FILE_DELETE')
 * @param {string} details - Event details
 * @param {string} token - JWT token
 */
export const logFileSharingEvent = async (eventType, details, token) => {
  try {
    await fetch(`${API_URL}/log`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        type: eventType,
        details,
        level: 'info'
      })
    });
  } catch (err) {
    console.error("Failed to log file sharing event:", err);
  }
};
