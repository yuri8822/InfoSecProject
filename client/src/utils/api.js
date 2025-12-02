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
