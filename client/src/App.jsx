/**
 * InfoSec Project - Main Application
 * Implements:
 * - Part 1: Cryptography (RSA-OAEP Key Generation)
 * - Part 2: Authentication (Bcrypt + JWT)
 * - Part 8: Key Storage (IndexedDB)
 */

import React, { useState, useEffect } from 'react';

// Utilities
import { generateKeyPair, exportKey } from './utils/crypto';
import { storePrivateKey, getPrivateKey } from './utils/indexedDB';
import { 
  registerUser, 
  loginUser, 
  logSecurityEvent, 
  fetchLogs as apiFetchLogs,
  fetchUsers as apiFetchUsers,
  fetchUserPublicKey
} from './utils/api';

// Components
import AuthForm from './components/AuthForm';
import Dashboard from './components/Dashboard';
import ChatWindow from './components/ChatWindow';
// PART 5: File Sharing Component
import FileSharing from './components/FileSharing';

export default function App() {
  const [view, setView] = useState('login'); // login, register, dashboard
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [user, setUser] = useState(null); // { token, username }
  const [keyStatus, setKeyStatus] = useState('checking'); // checking, present, missing
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]); // List of all registered users
  const [selectedUser, setSelectedUser] = useState(null); // Selected user for messaging
  const [showChat, setShowChat] = useState(false); // Show chat window
  // PART 5: Tab management for dashboard
  const [dashboardTab, setDashboardTab] = useState('overview'); // overview, files
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Check for existing session on page load
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

  // Check key status when user logs in
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

  // Fetch logs from server
  const handleFetchLogs = async () => {
    if (!user) return;
    try {
      const data = await apiFetchLogs(user.token);
      setLogs(data);
    } catch (err) {
      console.error("Fetch logs failed", err);
    }
  };

  // Fetch registered users
  const handleFetchUsers = async () => {
    if (!user) return;
    try {
      const data = await apiFetchUsers(user.token);
      setUsers(data);
    } catch (err) {
      console.error("Fetch users failed", err);
    }
  };

  // Handle user public key fetch
  const handleFetchPublicKey = async (username) => {
    // Open chat window with selected user
    setShowChat(true);
  };

  // Dashboard data polling
  useEffect(() => {
    if (view === 'dashboard') {
      checkKeyStatus();
      handleFetchLogs();
      handleFetchUsers();
      const interval = setInterval(handleFetchLogs, 5000); // Poll for logs every 5s
      return () => clearInterval(interval);
    }
  }, [view, user]);

  // Handle Registration
  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // 1. Generate Keys Client-Side (Part 1: Cryptography)
      const keyPair = await generateKeyPair();
      const publicKeyJwk = await exportKey(keyPair.publicKey);

      // 2. Register User + Public Key on Server (Part 2: Authentication)
      await registerUser(formData.username, formData.password, publicKeyJwk);

      // 3. Store Private Key Securely in IndexedDB (Part 8: Key Storage)
      await storePrivateKey(formData.username, keyPair.privateKey);

      // 4. Success
      setView('login');
      alert("Registration successful! Private key stored securely.");

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle Login
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Login via API (Part 2: Authentication)
      const data = await loginUser(formData.username, formData.password);

      // Set user session
      const userData = { username: formData.username, token: data.token };
      
      // Persist session to localStorage
      localStorage.setItem('secure_user_session', JSON.stringify(userData));
      
      setUser(userData);
      
      // Verify Private Key Existence (Part 8: Key Storage)
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

  // Handle Logout
  const handleLogout = () => {
    logSecurityEvent("AUTH_LOGOUT", "User logged out manually", user.token);
    
    // Clear session from localStorage
    localStorage.removeItem('secure_user_session');
    
    setUser(null);
    setView('login');
    setFormData({ username: '', password: '' });
  };

  // Handle view switching
  const handleSwitchView = (newView) => {
    setError('');
    setView(newView);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
      {view === 'login' && (
        <AuthForm 
          type="login" 
          formData={formData}
          setFormData={setFormData}
          onSubmit={handleLogin}
          loading={loading}
          error={error}
          onSwitchView={handleSwitchView}
        />
      )}
      
      {view === 'register' && (
        <AuthForm 
          type="register" 
          formData={formData}
          setFormData={setFormData}
          onSubmit={handleRegister}
          loading={loading}
          error={error}
          onSwitchView={handleSwitchView}
        />
      )}
      
      {view === 'dashboard' && (
        <div className="w-full flex flex-col">
          {/* PART 5: Dashboard Tabs */}
          <div className="mb-6 flex gap-2 border-b border-gray-200">
            <button
              onClick={() => setDashboardTab('overview')}
              className={`px-4 py-3 font-medium transition-colors ${
                dashboardTab === 'overview'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              Overview & Chat
            </button>
            <button
              onClick={() => setDashboardTab('files')}
              className={`px-4 py-3 font-medium transition-colors ${
                dashboardTab === 'files'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-gray-600 hover:text-gray-800'
              }`}
            >
              🔒 File Sharing (E2EE)
            </button>
          </div>

          {/* Dashboard Overview Tab */}
          {dashboardTab === 'overview' && (
            <Dashboard 
              user={user}
              keyStatus={keyStatus}
              logs={logs}
              users={users}
              selectedUser={selectedUser}
              onLogout={handleLogout}
              onRefreshLogs={handleFetchLogs}
              onRefreshUsers={handleFetchUsers}
              onSelectUser={setSelectedUser}
              onFetchPublicKey={handleFetchPublicKey}
            />
          )}

          {/* PART 5: File Sharing Tab */}
          {dashboardTab === 'files' && (
            <FileSharing user={user} />
          )}
        </div>
      )}

      {/* Chat Window Modal */}
      {showChat && selectedUser && (
        <ChatWindow 
          user={user}
          recipient={selectedUser}
          onClose={() => setShowChat(false)}
        />
      )}
    </div>
  );
}