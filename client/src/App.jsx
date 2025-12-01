import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, Lock, Key, Shield, Terminal, LogOut } from 'lucide-react';

// --- CONFIGURATION ---
const API_URL = "http://localhost:5000/api";

// --- INDEXEDDB HELPER (For Secure Key Storage) ---
const DB_NAME = "SecureMsgDB";
const STORE_NAME = "key_store";

const openDB = () => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onerror = () => reject("Error opening DB");
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

export default function App() {
  const [view, setView] = useState('login'); // login, register, dashboard
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [user, setUser] = useState(null); // { token, username, userId }
  const [keyStatus, setKeyStatus] = useState('checking'); // checking, generated, missing
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]); // List of all registered users
  const [selectedUser, setSelectedUser] = useState(null); // Selected user for messaging
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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

  // Fetch a specific user's public key (for your group members to use in Part 4)
  const fetchUserPublicKey = async (username) => {
    if (!user) return null;
    try {
      const res = await fetch(`${API_URL}/users/${username}/public-key`, {
        headers: { Authorization: `Bearer ${user.token}` }
      });
      const data = await res.json();
      if (res.ok) return data.publicKey;
      return null;
    } catch (err) {
      console.error("Fetch public key failed", err);
      return null;
    }
  };

  useEffect(() => {
    if (view === 'dashboard') {
      checkKeyStatus();
      fetchLogs();
      fetchUsers();
      const interval = setInterval(fetchLogs, 5000); // Poll for logs
      return () => clearInterval(interval);
    }
  }, [view, user]);

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
    const privKey = await getPrivateKey(user.username);
    setKeyStatus(privKey ? 'present' : 'missing');
  };

  // --- AUTH HANDLERS ---

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // 1. Generate Keys Client-Side
      const keyPair = await generateKeyPair();
      const publicKeyJwk = await exportKey(keyPair.publicKey);

      // 2. Register User + Public Key on Server
      const res = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: formData.username,
          password: formData.password,
          publicKey: publicKeyJwk
        })
      });
      
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.message || 'Registration failed');

      // 3. Store Private Key Securely in IndexedDB (NEVER sent to server)
      await storePrivateKey(formData.username, keyPair.privateKey);

      // 4. Log success
      // Note: In a real app, you might auto-login here.
      setView('login');
      alert("Registration successful! Private key stored securely.");

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
      
      // Verify Private Key Existence
      const privKey = await getPrivateKey(formData.username);
      if (!privKey) {
        logSecurityEvent("KEY_WARNING", "User logged in but private key missing from device", data.token);
        alert("Warning: This is a new device. You cannot decrypt old messages without your private key.");
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

  const AuthForm = ({ type }) => (
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
            onChange={(e) => setFormData({...formData, username: e.target.value})}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            required
            className="w-full px-4 py-2 mt-1 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
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
              <button 
                onClick={async () => {
                  const pubKey = await fetchUserPublicKey(selectedUser.username);
                  if (pubKey) {
                    console.log('Public Key:', pubKey);
                  }
                }}
                className="mt-2 w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded transition-colors"
              >
                Chat (E2EE)
              </button>
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
                <span className="text-sm font-medium text-gray-600">Algorithm</span>
                <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded">RSA-OAEP 2048</span>
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
              Your private key never leaves this device. It was generated using the Web Crypto API and is stored in a sandboxed database within your browser.
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
      {view === 'login' && <AuthForm type="login" />}
      {view === 'register' && <AuthForm type="register" />}
      {view === 'dashboard' && <Dashboard />}
    </div>
  );
}