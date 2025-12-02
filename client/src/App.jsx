import React, { useState, useEffect, useRef } from 'react';
import { AlertCircle, CheckCircle, Lock, Key, Shield, Terminal, LogOut, MessageSquare, ArrowLeft, Send } from 'lucide-react';
import { KeyExchange, generateLongTermKeyPair, exportPublicKey } from './security/secureKeyExchange.js';
import { encryptMessage, decryptMessage } from './security/endToEndMessageEncryption.js';

// --- CONFIGURATION ---
const API_URL = "http://localhost:5000/api";

// --- INDEXEDDB HELPER (For Secure Key Storage) ---
const DB_NAME = "SecureMsgDB";
const STORE_NAME = "key_store";

const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 3);
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

const storePrivateKey = async (userId, privateKey) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put({ userId, key: privateKey });
    request.onsuccess = () => resolve();
    request.onerror = () => reject("Error storing key");
  });
};

const getPrivateKey = async (userId) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(userId);
    request.onsuccess = () => resolve(request.result ? request.result.key : null);
    request.onerror = () => reject("Error retrieving key");
  });
};

// Store Ed25519 signing keys (for key exchange protocol)
const storeSigningKeys = async (userId, signingKeys) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.get(userId).onsuccess = (e) => {
      const existing = e.target.result || { userId };
      existing.signingKeys = signingKeys; // {privateKey, publicKey}
      const request = store.put(existing);
      request.onsuccess = () => resolve();
      request.onerror = () => reject("Error storing signing keys");
    };
  });
};

const getSigningKeys = async (userId) => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(userId);
    request.onsuccess = () => resolve(request.result?.signingKeys || null);
    request.onerror = () => reject("Error retrieving signing keys");
  });
};

// --- LOGGING HELPER ---
const logSecurityEvent = async (type, details, token = null) => {
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

// AuthForm component moved outside to prevent recreation on each render
const AuthForm = ({ type, formData, setFormData, error, setError, setView, handleLogin, handleRegister, loading }) => (
  <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-xl shadow-lg border border-gray-100">
    <div className="text-center">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-100 mb-4">
        <Shield className="w-6 h-6 text-blue-600" />
      </div>
      <h2 className="text-2xl font-bold text-gray-900">
        {type === 'login' ? 'Secure Login' : 'Generate Identity'}
      </h2>
      <p className="mt-2 text-sm text-gray-500">
        {type === 'login' 
          ? 'Authenticate to access your secure vault' 
          : 'Register to generate your unique RSA-2048 Keypair'}
      </p>
    </div>

    {error && (
      <div className="p-3 text-sm text-red-600 bg-red-50 rounded-lg flex items-center gap-2">
        <AlertCircle size={16} />
        {error}
      </div>
    )}

    <form onSubmit={type === 'login' ? handleLogin : handleRegister} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700">Username</label>
        <input
          type="text"
          required
          className="w-full px-4 py-2 mt-1 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
          value={formData.username}
          onChange={(e) => {
            const value = e.target.value;
            setFormData(prev => ({...prev, username: value}));
          }}
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700">Password</label>
        <input
          type="password"
          required
          className="w-full px-4 py-2 mt-1 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
          value={formData.password}
          onChange={(e) => {
            const value = e.target.value;
            setFormData(prev => ({...prev, password: value}));
          }}
        />
      </div>
      
      <button
        type="submit"
        disabled={loading}
        className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
      >
        {loading ? "Processing..." : (type === 'login' ? "Sign In" : "Generate Keys & Register")}
        {!loading && type !== 'login' && <Key size={16} />}
      </button>
    </form>

    <div className="text-center text-sm text-gray-500">
      {type === 'login' ? (
        <p>Need an identity? <button onClick={() => {setError(''); setView('register')}} className="text-blue-600 font-medium hover:underline">Create one</button></p>
      ) : (
        <p>Already have keys? <button onClick={() => {setError(''); setView('login')}} className="text-blue-600 font-medium hover:underline">Sign in</button></p>
      )}
    </div>
  </div>
);

export default function App() {
  const [view, setView] = useState('login'); // login, register, dashboard, chat
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [user, setUser] = useState(null); // { token, username, userId }
  const [keyStatus, setKeyStatus] = useState('checking'); // checking, generated, missing
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]); // List of all registered users
  const [selectedUser, setSelectedUser] = useState(null); // Selected user for messaging
  const [chatPeer, setChatPeer] = useState(null); // User we're chatting with
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [keyExchangeStatus, setKeyExchangeStatus] = useState(null); // {peerId, status, sessionKey}
  const [keyExchangeMessages, setKeyExchangeMessages] = useState([]);
  const activeKeyExchanges = useRef(new Map()); // Map<peerId, KeyExchange instance>
  const processedMessageIds = useRef(new Set()); // Track processed message IDs to avoid duplicates
  const sessionKeys = useRef(new Map()); // Map<peerId, sessionKey ArrayBuffer> - Store established session keys
  const [messages, setMessages] = useState([]); // Messages for current chat
  const [messageInput, setMessageInput] = useState(''); // Current message input
  const [sendingMessage, setSendingMessage] = useState(false); // Loading state for sending

  // NEW: Check for existing session on page load
  useEffect(() => {
    const savedSession = localStorage.getItem('secure_user_session');
    if (savedSession) {
      try {
        const parsedUser = JSON.parse(savedSession);
        setUser(parsedUser);
        setView('dashboard');
      } catch (e) {
        localStorage.removeItem('secure_user_session');
      }
    }
  }, []);

  // Fetch logs for dashboard
  const fetchLogs = async () => {
    if (!user) return;
    try {
      const res = await fetch(`${API_URL}/logs`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      const data = await res.json();
      if (res.ok) setLogs(data);
    } catch (err) {
      console.error("Fetch logs failed", err);
    }
  };

  // Fetch registered users
  const fetchUsers = async () => {
    if (!user) return;
    try {
      const res = await fetch(`${API_URL}/users`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      const data = await res.json();
      if (res.ok) setUsers(data);
    } catch (err) {
      console.error("Fetch users failed", err);
    }
  };

  // Fetch a specific user's public keys (RSA and Ed25519)
  const fetchUserPublicKeys = async (username) => {
    if (!user) return null;
    try {
      const res = await fetch(`${API_URL}/users/${username}/public-key`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      const data = await res.json();
      if (res.ok) return {
        rsaPublicKey: data.publicKey,
        signingPublicKey: data.signingPublicKey
      };
      return null;
    } catch (err) {
      console.error("Fetch public key failed", err);
      return null;
    }
  };

  // Fetch key exchange messages
  const fetchKeyExchangeMessages = async () => {
    if (!user) return;
    try {
      const res = await fetch(`${API_URL}/key-exchange/messages`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      const data = await res.json();
      if (res.ok) {
        const messages = data.messages || [];
        setKeyExchangeMessages(messages);
        
        // Only process messages if we don't have established sessions for those peers
        const messagesToProcess = messages.filter(msg => {
          // Skip if we already have an established session with this peer
          if (keyExchangeStatus && keyExchangeStatus.peerId === msg.from && keyExchangeStatus.status === 'established') {
            return false;
          }
          return true;
        });
        
        // Process any pending messages
        for (const msg of messagesToProcess) {
          await processKeyExchangeMessage(msg);
        }
      }
    } catch (err) {
      console.error("Fetch key exchange messages failed", err);
    }
  };

  // Process incoming key exchange message
  const processKeyExchangeMessage = async (msg) => {
    // Skip if already processed
    if (processedMessageIds.current.has(msg.messageId)) {
      return;
    }

    // Skip if we already have an established session with this peer
    if (keyExchangeStatus && keyExchangeStatus.peerId === msg.from && keyExchangeStatus.status === 'established') {
      console.log(`[${user.username}] Session already established with ${msg.from}, deleting message ${msg.messageId}`);
      // Delete the message to clean up
      try {
        await fetch(`${API_URL}/key-exchange/messages/${msg.messageId}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${user.token}` }
        });
        processedMessageIds.current.add(msg.messageId);
      } catch (e) {
        // Ignore delete errors
      }
      return;
    }

    // Mark as processing
    processedMessageIds.current.add(msg.messageId);

    try {
      const signingKeys = await getSigningKeys(user.username);
      if (!signingKeys) {
        console.error("Signing keys not found");
        return;
      }

      const peerKeys = await fetchUserPublicKeys(msg.from);
      if (!peerKeys) {
        console.error("Peer keys not found");
        return;
      }

      // Determine if this is an init or response message
      const messageData = typeof msg.message === 'string' ? JSON.parse(msg.message) : msg.message;

      if (messageData.type === 'init') {
        // We received an init message, create a response
        // Extract init fields (remove 'type' field)
        const { type, ...initMessage } = messageData;
        const keyExchange = new KeyExchange(user.username, signingKeys);
        const response = await keyExchange.createResponseMessage(initMessage, peerKeys.signingPublicKey);
        
        // Derive the session key as the responder (we have all the info we need).
        const sessionKey = await keyExchange.deriveSessionKeyAsResponder();
        
        // Debug: Log session key details
        const keyBytes = new Uint8Array(sessionKey);
        console.log(`[RESPONDER] Storing session key for ${msg.from}:`, {
          keyLength: sessionKey.byteLength,
          first8Bytes: Array.from(keyBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(':')
        });
        
        // Store the session key for message encryption.
        sessionKeys.current.set(msg.from, sessionKey);
        
        // Update key exchange status.
        setKeyExchangeStatus({
          peerId: msg.from,
          status: 'established',
          sessionKey: sessionKey
        });
        
        // Send response back
        const messageId = `response-${Date.now()}-${Math.random()}`;
        await fetch(`${API_URL}/key-exchange/send`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${user.token}`
          },
          body: JSON.stringify({
            to: msg.from,
            message: { type: 'response', ...response },
            messageId
          })
        });

        // Delete the processed message
        await fetch(`${API_URL}/key-exchange/messages/${msg.messageId}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${user.token}` }
        });

        logSecurityEvent("KEY_EXCHANGE_RESPONSE", `Responded to key exchange from ${msg.from} and derived session key`, user.token);
        
        // Auto-open chat for the receiver when key exchange completes.
        if (view === 'dashboard') {
          setChatPeer({ username: msg.from });
          setView('chat');
          // Fetch messages after a short delay to ensure state is set
          setTimeout(() => fetchMessages(msg.from), 500);
        }
        
        // Mark as processed
        processedMessageIds.current.add(msg.messageId);
      } else if (messageData.type === 'response') {
        // We received a response, finalize the session
        console.log("Processing response message from:", msg.from);
        console.log("Active key exchanges:", Array.from(activeKeyExchanges.current.keys()));
        console.log("Current keyExchangeStatus:", keyExchangeStatus);
        
        const keyExchange = activeKeyExchanges.current.get(msg.from);
        console.log("Found keyExchange:", !!keyExchange);
        
        if (keyExchange && keyExchangeStatus && keyExchangeStatus.peerId === msg.from && keyExchangeStatus.status === 'init_sent') {
          try {
            console.log("Finalizing session with peer:", msg.from);
            // Extract response fields (remove 'type' field)
            const { type, ...responseMessage } = messageData;
            const sessionKey = await keyExchange.finalizeSession(responseMessage, peerKeys.signingPublicKey);
            
            // Debug: Log session key details
            const keyBytes = new Uint8Array(sessionKey);
            console.log(`[INITIATOR] Storing session key for ${msg.from}:`, {
              keyLength: sessionKey.byteLength,
              first8Bytes: Array.from(keyBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(':')
            });
            
            // Store the session key for message encryption.
            sessionKeys.current.set(msg.from, sessionKey);
            
            setKeyExchangeStatus({
              peerId: msg.from,
              status: 'established',
              sessionKey: sessionKey
            });

            // Clean up the key exchange instance
            activeKeyExchanges.current.delete(msg.from);

            logSecurityEvent("KEY_EXCHANGE_SUCCESS", `Key exchange established with ${msg.from}`, user.token);
            
            // If we're waiting to chat with this peer, open chat now
            if (chatPeer && chatPeer.username === msg.from && view !== 'chat') {
              setView('chat');
              fetchMessages(msg.from);
            }
            
            // Delete the processed message
            await fetch(`${API_URL}/key-exchange/messages/${msg.messageId}`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${user.token}` }
            });
          } catch (err) {
            logSecurityEvent("KEY_EXCHANGE_FINALIZE_ERROR", `Error finalizing key exchange: ${err.message}`, user.token);
            console.error("Error finalizing key exchange:", err);
            activeKeyExchanges.current.delete(msg.from);
            // Remove from processed set so we can retry
            processedMessageIds.current.delete(msg.messageId);
          }
        } else {
          console.error("Key exchange state check failed:", {
            hasKeyExchange: !!keyExchange,
            keyExchangeStatus: keyExchangeStatus,
            expectedPeerId: msg.from,
            statusMatches: keyExchangeStatus?.status === 'init_sent',
            peerIdMatches: keyExchangeStatus?.peerId === msg.from
          });
          
          // Try to recover: if we have the keyExchange but state is wrong, try to finalize anyway
          if (keyExchange) {
            try {
              console.log("Attempting to recover key exchange state...");
              const { type, ...responseMessage } = messageData;
              const sessionKey = await keyExchange.finalizeSession(responseMessage, peerKeys.signingPublicKey);
              
              // Store the session key for message encryption.
              sessionKeys.current.set(msg.from, sessionKey);
              
              setKeyExchangeStatus({
                peerId: msg.from,
                status: 'established',
                sessionKey: sessionKey
              });
              
              activeKeyExchanges.current.delete(msg.from);
              logSecurityEvent("KEY_EXCHANGE_SUCCESS", `Key exchange established with ${msg.from} (recovered)`, user.token);
              
              // If we're waiting to chat with this peer, open chat now
              if (chatPeer && chatPeer.username === msg.from && view !== 'chat') {
                setView('chat');
                fetchMessages(msg.from);
              }
              
              // Delete the processed message
              await fetch(`${API_URL}/key-exchange/messages/${msg.messageId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${user.token}` }
              });
            } catch (recoverErr) {
              console.error("Recovery failed:", recoverErr);
              logSecurityEvent("KEY_EXCHANGE_STATE_LOST", `Key exchange state lost for ${msg.from} - please re-initiate`, user.token);
              // Remove from processed set so we can retry
              processedMessageIds.current.delete(msg.messageId);
            }
          } else {
            logSecurityEvent("KEY_EXCHANGE_STATE_LOST", `Key exchange state lost for ${msg.from} - please re-initiate`, user.token);
            // Delete the message since we can't process it
            await fetch(`${API_URL}/key-exchange/messages/${msg.messageId}`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${user.token}` }
            });
          }
        }
      }
    } catch (err) {
      // Remove from processed set on error so we can retry
      processedMessageIds.current.delete(msg.messageId);
      console.error("Error processing key exchange message:", err);
      logSecurityEvent("KEY_EXCHANGE_ERROR", `Error processing message: ${err.message}`, user.token);
    }
  };

  // Start chat with a peer (initiates key exchange if needed, then opens chat)
  const startChat = async (peerUsername) => {
    if (!user) return;
    
    // Prevent self-chat
    if (peerUsername === user.username) {
      setError("Cannot chat with yourself");
      return;
    }
    
    setLoading(true);
    setError('');

    try {
      // Check if we already have a session key for this peer
      const existingSessionKey = sessionKeys.current.get(peerUsername);
      
      if (existingSessionKey) {
        // We already have a session, go straight to chat
        setChatPeer({ username: peerUsername });
        setView('chat');
        setLoading(false);
        return;
      }

      // Check if key exchange is in progress
      if (keyExchangeStatus && keyExchangeStatus.peerId === peerUsername && keyExchangeStatus.status === 'init_sent') {
        setError("Key exchange in progress. Please wait...");
        setLoading(false);
        return;
      }

      // Get our signing keys
      const signingKeys = await getSigningKeys(user.username);
      if (!signingKeys) {
        throw new Error("Signing keys not found. Please re-register.");
      }

      // Get peer's public keys
      const peerKeys = await fetchUserPublicKeys(peerUsername);
      if (!peerKeys) {
        throw new Error("Could not fetch peer's public keys. The user may not exist.");
      }
      if (!peerKeys.signingPublicKey) {
        throw new Error("The selected user has not completed key setup. They need to re-register to enable messaging.");
      }

      // Create key exchange instance
      const keyExchange = new KeyExchange(user.username, signingKeys);
      const initMessage = await keyExchange.createInitMessage();
      
      // Validate init message structure
      if (!initMessage.id || !initMessage.ephPub || !initMessage.nonce || !initMessage.signature) {
        throw new Error("Failed to create valid key exchange message");
      }

      // Send init message
      const messageId = `init-${Date.now()}-${Math.random()}`;
      const res = await fetch(`${API_URL}/key-exchange/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${user.token}`
        },
        body: JSON.stringify({
          to: peerUsername,
          message: { type: 'init', ...initMessage },
          messageId
        })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ message: "Unknown error" }));
        throw new Error(errorData.message || `Failed to send key exchange message (${res.status})`);
      }

      // Store key exchange instance in ref BEFORE setting state
      activeKeyExchanges.current.set(peerUsername, keyExchange);
      
      // Store key exchange state
      setKeyExchangeStatus({
        peerId: peerUsername,
        status: 'init_sent'
      });
      
      // Set chat peer and wait for key exchange
      setChatPeer({ username: peerUsername });
      
      // Immediately check for any pending response messages
      setTimeout(() => fetchKeyExchangeMessages(), 500);

      logSecurityEvent("KEY_EXCHANGE_INIT", `Initiated key exchange with ${peerUsername} for chat`, user.token);
      
      // Poll for key exchange completion, then open chat
      const checkInterval = setInterval(async () => {
        const sessionKey = sessionKeys.current.get(peerUsername);
        if (sessionKey) {
          clearInterval(checkInterval);
          setView('chat');
          setLoading(false);
          fetchMessages(peerUsername);
        }
      }, 500);
      
      // Timeout after 30 seconds
      setTimeout(() => {
        clearInterval(checkInterval);
        if (!sessionKeys.current.get(peerUsername)) {
          setError("Key exchange timed out. Please try again.");
          setLoading(false);
        }
      }, 30000);

    } catch (err) {
      setError(err.message);
      logSecurityEvent("KEY_EXCHANGE_INIT_FAIL", `Failed to initiate key exchange: ${err.message}`, user.token);
      setLoading(false);
    }
  };

  // Initiate key exchange with a peer (legacy function, kept for compatibility)
  const initiateKeyExchange = async (peerUsername) => {
    if (!user) return;
    
    // Prevent self-exchange
    if (peerUsername === user.username) {
      setError("Cannot initiate key exchange with yourself");
      return;
    }
    
    setLoading(true);
    setError('');

    try {
      // Get our signing keys
      const signingKeys = await getSigningKeys(user.username);
      if (!signingKeys) {
        throw new Error("Signing keys not found. Please re-register.");
      }

      // Get peer's public keys
      const peerKeys = await fetchUserPublicKeys(peerUsername);
      if (!peerKeys) {
        throw new Error("Could not fetch peer's public keys. The user may not exist.");
      }
      if (!peerKeys.signingPublicKey) {
        throw new Error("The selected user has not completed key setup. They need to re-register to enable key exchange.");
      }

      // Create key exchange instance
      const keyExchange = new KeyExchange(user.username, signingKeys);
      const initMessage = await keyExchange.createInitMessage();
      
      // Validate init message structure
      if (!initMessage.id || !initMessage.ephPub || !initMessage.nonce || !initMessage.signature) {
        throw new Error("Failed to create valid key exchange message");
      }

      // Send init message
      const messageId = `init-${Date.now()}-${Math.random()}`;
      const res = await fetch(`${API_URL}/key-exchange/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${user.token}`
        },
        body: JSON.stringify({
          to: peerUsername,
          message: { type: 'init', ...initMessage },
          messageId
        })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ message: "Unknown error" }));
        throw new Error(errorData.message || `Failed to send key exchange message (${res.status})`);
      }

      // Store key exchange instance in ref BEFORE setting state
      activeKeyExchanges.current.set(peerUsername, keyExchange);
      console.log("Stored key exchange for:", peerUsername, "Active exchanges:", Array.from(activeKeyExchanges.current.keys()));
      
      // Store key exchange state
      setKeyExchangeStatus({
        peerId: peerUsername,
        status: 'init_sent'
      });
      
      // Immediately check for any pending response messages
      setTimeout(() => fetchKeyExchangeMessages(), 500);

      logSecurityEvent("KEY_EXCHANGE_INIT", `Initiated key exchange with ${peerUsername}`, user.token);
      alert("Key exchange initiated! Waiting for response...");

    } catch (err) {
      setError(err.message);
      logSecurityEvent("KEY_EXCHANGE_INIT_FAIL", `Failed to initiate key exchange: ${err.message}`, user.token);
    } finally {
      setLoading(false);
    }
  };

  // Fetch messages for a chat
  const fetchMessages = async (peerUsername) => {
    if (!user || !peerUsername) return;
    try {
      const res = await fetch(`${API_URL}/messages/${peerUsername}`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      
      if (!res.ok) {
        if (res.status === 404) {
          // No messages yet, that's okay
          setMessages([]);
          return;
        }
        console.error("Failed to fetch messages:", res.status, res.statusText);
        return;
      }
      
      const data = await res.json();
      if (!data || !data.messages) {
        setMessages([]);
        return;
      }
      
      // Decrypt messages
      const sessionKey = sessionKeys.current.get(peerUsername);
      if (!sessionKey) {
        console.error("No session key for decryption");
        setMessages([]);
        return;
      }
      
      // Debug: Log session key being used for decryption
      const keyBytes = new Uint8Array(sessionKey);
      console.log(`[DECRYPT] Using session key for ${peerUsername}:`, {
        keyLength: sessionKey.byteLength,
        first8Bytes: Array.from(keyBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(':')
      });

      const decryptedMessages = await Promise.all(
        data.messages.map(async (msg) => {
          try {
            console.log(`[DECRYPT] Attempting to decrypt message from ${msg.from}:`, {
              hasSessionKey: !!sessionKey,
              sessionKeyLength: sessionKey?.byteLength,
              ciphertextLength: msg.ciphertext?.length,
              ivLength: msg.iv?.length,
              tagLength: msg.tag?.length
            });
            
            const plaintext = await decryptMessage(
              {
                ciphertext: msg.ciphertext,
                iv: msg.iv,
                tag: msg.tag
              },
              sessionKey
            );
            
            console.log(`[DECRYPT] Successfully decrypted message from ${msg.from}`);
            return {
              ...msg,
              plaintext: plaintext,
              isDecrypted: true
            };
          } catch (err) {
            console.error(`[DECRYPT] Failed to decrypt message from ${msg.from}:`, err);
            console.error(`[DECRYPT] Message details:`, {
              from: msg.from,
              to: msg.to,
              timestamp: msg.timestamp,
              hasSessionKey: !!sessionKey,
              sessionKeyLength: sessionKey?.byteLength
            });
            return {
              ...msg,
              plaintext: `[Decryption failed: ${err.message}]`,
              isDecrypted: false
            };
          }
        })
      );
      setMessages(decryptedMessages);
    } catch (err) {
      // Handle JSON parse errors (when server returns HTML 404 page)
      if (err.message.includes('JSON') || err.message.includes('DOCTYPE')) {
        console.warn("Server returned non-JSON response (likely 404 page), treating as no messages");
        setMessages([]);
      } else {
        console.error("Fetch messages failed", err);
      }
    }
  };

  // Send an encrypted message
  const sendMessage = async (plaintext) => {
    console.log("sendMessage called with:", { plaintext, user: !!user, chatPeer: chatPeer?.username });
    
    if (!user || !chatPeer || !plaintext.trim()) {
      const errorMsg = `Cannot send message: user=${!!user}, chatPeer=${!!chatPeer}, plaintext="${plaintext.trim()}"`;
      console.error(errorMsg);
      setError(errorMsg);
      return;
    }

    const sessionKey = sessionKeys.current.get(chatPeer.username);
    console.log("Session key check:", {
      chatPeerUsername: chatPeer.username,
      hasSessionKey: !!sessionKey,
      allSessionKeys: Array.from(sessionKeys.current.keys())
    });
    
    if (!sessionKey) {
      const errorMsg = "No session key established. Please wait for key exchange to complete.";
      setError(errorMsg);
      console.error(errorMsg, "Available session keys:", Array.from(sessionKeys.current.keys()));
      return;
    }

    setSendingMessage(true);
    setError(''); // Clear previous errors

    try {
      console.log("Encrypting message for:", chatPeer.username, "Message length:", plaintext.length);
      // Encrypt the message
      const encrypted = await encryptMessage(plaintext, sessionKey);
      console.log("Message encrypted successfully", {
        ciphertextLength: encrypted.ciphertext.length,
        ivLength: encrypted.iv.length,
        tagLength: encrypted.tag.length
      });

      // Send to server
      console.log("Sending to server:", `${API_URL}/messages/send`);
      const res = await fetch(`${API_URL}/messages/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${user.token}`
        },
        body: JSON.stringify({
          to: chatPeer.username,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          tag: encrypted.tag
        })
      });

      console.log("Server response:", res.status, res.statusText);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ message: "Unknown error" }));
        console.error("Failed to send message:", res.status, errorData);
        throw new Error(errorData.message || `Failed to send message (${res.status})`);
      }

      const responseData = await res.json();
      console.log("Message sent successfully:", responseData);
      
      // Clear input and refresh messages
      setMessageInput('');
      
      // Refresh messages immediately
      await fetchMessages(chatPeer.username);
      
      logSecurityEvent("MESSAGE_SENT", `Sent encrypted message to ${chatPeer.username}`, user.token);
    } catch (err) {
      console.error("Error sending message:", err);
      setError(err.message);
      logSecurityEvent("MESSAGE_SEND_FAIL", `Failed to send message: ${err.message}`, user.token);
    } finally {
      setSendingMessage(false);
    }
  };

  useEffect(() => {
    if (view === 'dashboard') {
      checkKeyStatus();
      fetchLogs();
      fetchUsers();
      fetchKeyExchangeMessages();
      const logInterval = setInterval(fetchLogs, 5000); // Poll for logs
      const keyExchangeInterval = setInterval(fetchKeyExchangeMessages, 1000); // Poll for key exchange messages every 1 second
      return () => {
        clearInterval(logInterval);
        clearInterval(keyExchangeInterval);
      };
    } else if (view === 'chat' && chatPeer) {
      // Poll for new messages when in chat view
      fetchMessages(chatPeer.username);
      const messageInterval = setInterval(() => fetchMessages(chatPeer.username), 2000);
      return () => clearInterval(messageInterval);
    }
  }, [view, user, chatPeer]);

  // --- CRYPTO FUNCTIONS ---

  // Generate RSA-OAEP Key Pair (2048 bit)
  const generateKeyPair = async () => {
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

  // Export Key to JWK (JSON Web Key) format for transport
  const exportKey = async (key) => {
    return await window.crypto.subtle.exportKey("jwk", key);
  };

  const checkKeyStatus = async () => {
    if (!user) return;
    try {
      const privKey = await getPrivateKey(user.username);
      setKeyStatus(privKey ? 'present' : 'missing');
    } catch (err) {
      console.error('Error checking key status:', err);
      setKeyStatus('missing');
    }
  };

  // --- AUTH HANDLERS ---

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // 1. Generate RSA-OAEP Key Pair (for encryption/decryption)
      const keyPair = await generateKeyPair();
      const publicKeyJwk = await exportKey(keyPair.publicKey);

      // 2. Generate Ed25519 Signing Key Pair (for key exchange protocol)
      const signingKeyPair = await generateLongTermKeyPair();
      const signingPublicKeyJwk = await exportPublicKey(signingKeyPair.publicKey);

      // 3. Register User + Public Keys on Server
      const res = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: formData.username,
          password: formData.password,
          publicKey: publicKeyJwk, // RSA public key
          signingPublicKey: signingPublicKeyJwk // Ed25519 public key
        })
      });
      
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.message || 'Registration failed');

      // 4. Store Private Keys Securely in IndexedDB (NEVER sent to server)
      await storePrivateKey(formData.username, keyPair.privateKey);
      await storeSigningKeys(formData.username, {
        privateKey: signingKeyPair.privateKey,
        publicKey: signingKeyPair.publicKey
      });

      // 5. Log success
      // Note: In a real app, you might auto-login here.
      setView('login');
      alert("Registration successful! Private keys stored securely.");

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData)
      });
      
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Login failed');

      // Set user session
      const userData = { username: formData.username, token: data.token };
      
      // NEW: Persist session to localStorage
      localStorage.setItem('secure_user_session', JSON.stringify(userData));
      
      setUser(userData);
      
      // Verify Private Keys Existence
      const privKey = await getPrivateKey(formData.username);
      const signingKeys = await getSigningKeys(formData.username);
      if (!privKey || !signingKeys) {
        logSecurityEvent("KEY_WARNING", "User logged in but private keys missing from device", data.token);
        alert("Warning: This is a new device. You cannot use key exchange without your signing keys. Please re-register if needed.");
      }

      setView('dashboard');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    logSecurityEvent("AUTH_LOGOUT", "User logged out manually", user.token);
    
    // NEW: Clear session from localStorage
    localStorage.removeItem('secure_user_session');
    
    setUser(null);
    setView('login');
    setFormData({ username: '', password: '' });
  };

  // --- UI COMPONENTS ---

  const Dashboard = () => (
    <div className="w-full max-w-5xl space-y-6">
      <header className="flex items-center justify-between bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-700 font-bold text-xl">
            {user.username[0].toUpperCase()}
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">Welcome, {user.username}</h1>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
              Secure Connection Established
            </div>
          </div>
        </div>
        <button 
          onClick={handleLogout}
          className="flex items-center gap-2 px-4 py-2 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors"
        >
          <LogOut size={18} />
          Logout
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Directory Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Shield className="text-blue-500" />
              <h3 className="text-lg font-semibold text-gray-800">Registered Users</h3>
            </div>
            <button onClick={fetchUsers} className="text-xs text-blue-600 hover:underline">Refresh</button>
          </div>
          
          <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
            {users.length === 0 ? (
              <div className="text-center text-gray-400 text-sm py-8">No other users found</div>
            ) : (
              users.map((u) => (
                <div 
                  key={u._id}
                  onClick={() => setSelectedUser(u)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedUser?._id === u._id 
                      ? 'bg-blue-50 border-blue-300 shadow-sm' 
                      : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-full flex items-center justify-center text-white font-bold text-sm">
                      {u.username[0].toUpperCase()}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium text-gray-800">{u.username}</div>
                      <div className="text-xs text-gray-400">
                        Joined {new Date(u.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          {selectedUser && (
            <div className="mt-4 p-3 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200">
              <div className="text-xs font-semibold text-blue-700 mb-1">Selected User</div>
              <div className="font-medium text-gray-800">{selectedUser.username}</div>
              <div className="mt-2 space-y-2">
                <button 
                  onClick={() => startChat(selectedUser.username)}
                  disabled={loading}
                  className="w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white text-xs font-medium rounded transition-colors flex items-center justify-center gap-2"
                >
                  <MessageSquare size={14} />
                  {loading ? 'Connecting...' : 'Chat'}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Key Management Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center gap-2 mb-4">
            <Key className="text-amber-500" />
            <h3 className="text-lg font-semibold text-gray-800">Key Management</h3>
          </div>
          
          <div className="space-y-4">
            <div className="p-4 bg-gray-50 rounded-lg border border-gray-100">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-600">Storage Mechanism</span>
                <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">IndexedDB</span>
              </div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-600">RSA Key</span>
                <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded">RSA-OAEP 2048</span>
              </div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-600">Signing Key</span>
                <span className="text-xs bg-indigo-100 text-indigo-700 px-2 py-1 rounded">Ed25519</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-600">Private Key Status</span>
                {keyStatus === 'present' ? (
                  <span className="flex items-center gap-1 text-xs text-green-600 font-medium bg-green-50 px-2 py-1 rounded">
                    <CheckCircle size={12} /> Securely Stored
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-red-600 font-medium bg-red-50 px-2 py-1 rounded">
                    <AlertCircle size={12} /> Missing on Device
                  </span>
                )}
              </div>
            </div>
            <p className="text-xs text-gray-400">
              Your private keys (RSA-OAEP and Ed25519) never leave this device. They were generated using the Web Crypto API and are stored in a sandboxed database within your browser.
            </p>
          </div>
        </div>

        {/* Security Audit Log Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex flex-col h-80">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Terminal className="text-slate-700" />
              <h3 className="text-lg font-semibold text-gray-800">Server-Side Audit Logs</h3>
            </div>
            <button onClick={fetchLogs} className="text-xs text-blue-600 hover:underline">Refresh</button>
          </div>
          
          <div className="flex-1 overflow-y-auto bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-300 space-y-2 custom-scrollbar">
            {logs.length === 0 ? (
              <div className="text-center text-slate-600 italic mt-10">No logs found</div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="border-b border-slate-800 pb-2 mb-2 last:border-0 last:mb-0 last:pb-0">
                  <div className="flex justify-between text-slate-500 mb-1">
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className={`uppercase font-bold ${
                      log.type.includes('FAIL') || log.type.includes('WARNING') ? 'text-red-400' : 
                      log.type.includes('KEY') ? 'text-amber-400' : 'text-green-400'
                    }`}>{log.type}</span>
                  </div>
                  <div className="text-slate-200">{log.details}</div>
                  <div className="text-slate-600 text-[10px] mt-0.5">IP: {log.ipAddress}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
      {view === 'login' && (
        <AuthForm 
          type="login" 
          formData={formData}
          setFormData={setFormData}
          error={error}
          setError={setError}
          setView={setView}
          handleLogin={handleLogin}
          handleRegister={handleRegister}
          loading={loading}
        />
      )}
      {view === 'register' && (
        <AuthForm 
          type="register" 
          formData={formData}
          setFormData={setFormData}
          error={error}
          setError={setError}
          setView={setView}
          handleLogin={handleLogin}
          handleRegister={handleRegister}
          loading={loading}
        />
      )}
      {view === 'dashboard' && <Dashboard />}
      {view === 'chat' && chatPeer && (
        <div className="w-full max-w-4xl h-[90vh] flex flex-col bg-white rounded-xl shadow-lg border border-gray-100">
          {/* Chat Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-200">
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  setView('dashboard');
                  setChatPeer(null);
                  setMessages([]);
                }}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <ArrowLeft size={20} />
              </button>
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-full flex items-center justify-center text-white font-bold">
                {chatPeer.username[0].toUpperCase()}
              </div>
              <div>
                <h2 className="font-semibold text-gray-900">{chatPeer.username}</h2>
                <div className="text-xs text-gray-500 flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  End-to-end encrypted
                </div>
              </div>
            </div>
          </div>

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-50">
            {messages.length === 0 ? (
              <div className="text-center text-gray-400 mt-10">
                <MessageSquare size={48} className="mx-auto mb-2 opacity-50" />
                <p>No messages yet. Start the conversation!</p>
              </div>
            ) : (
              messages.map((msg, idx) => {
                const isFromMe = msg.from === user.username;
                return (
                  <div
                    key={idx}
                    className={`flex ${isFromMe ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                        isFromMe
                          ? 'bg-blue-600 text-white'
                          : 'bg-white text-gray-900 border border-gray-200'
                      }`}
                    >
                      <div className="text-sm">{msg.plaintext}</div>
                      <div className={`text-xs mt-1 ${
                        isFromMe ? 'text-blue-100' : 'text-gray-400'
                      }`}>
                        {new Date(msg.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Message Input */}
          <div className="p-4 border-t border-gray-200">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                sendMessage(messageInput);
              }}
              className="flex gap-2"
            >
              <input
                type="text"
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Type a message..."
                className="flex-1 px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                disabled={!sessionKeys.current.get(chatPeer.username)}
              />
              <button
                type="submit"
                disabled={!messageInput.trim() || !sessionKeys.current.get(chatPeer.username) || sendingMessage}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg transition-colors flex items-center gap-2"
              >
                {sendingMessage ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Sending...
                  </>
                ) : (
                  <>
                    <Send size={18} />
                    Send
                  </>
                )}
              </button>
            </form>
            <div className="mt-2 space-y-1">
              {!sessionKeys.current.get(chatPeer.username) && (
                <p className="text-xs text-gray-500">Establishing secure connection...</p>
              )}
              {sessionKeys.current.get(chatPeer.username) && (
                <p className="text-xs text-green-600">✓ Secure connection established</p>
              )}
              {error && (
                <div className="p-2 text-xs text-red-600 bg-red-50 rounded">
                  {error}
                </div>
              )}
              {/* Debug info - remove in production */}
              <div className="text-xs text-gray-400">
                Session keys: {Array.from(sessionKeys.current.keys()).join(', ') || 'none'}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}