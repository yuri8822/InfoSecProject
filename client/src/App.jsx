
import React, { useState, useEffect } from 'react';

import { generateKeyPair, exportKey } from './utils/crypto';
import { 
  customKX_generateLongTermSigningKeyPair, 
  customKX_exportPublicKeyJwk 
} from './utils/crypto';
import { storePrivateKey, getPrivateKey, storeSigningPrivateKey } from './utils/indexedDB';
import { 
  registerUser, 
  loginUser, 
  logSecurityEvent, 
  fetchLogs as apiFetchLogs,
  fetchUsers as apiFetchUsers,
  fetchUserPublicKey
} from './utils/api';

import AuthForm from './components/AuthForm';
import Dashboard from './components/Dashboard';
import ReplayAttackDemo from './components/ReplayAttackDemo';
import MitmAttackDemo from './components/MitmAttackDemo';
import ChatWindow from './components/ChatWindow';

export default function App() {
  const [view, setView] = useState('login'); // login, register, dashboard, replay-demo
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [user, setUser] = useState(null); // { token, username }
  const [keyStatus, setKeyStatus] = useState('checking'); // checking, present, missing
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]); // List of all registered users
  const [selectedUser, setSelectedUser] = useState(null); // Selected user for messaging
  const [chatContext, setChatContext] = useState(null); // Active chat recipient + public key
  const [showChat, setShowChat] = useState(false); // Show chat window
  const [mitmContext, setMitmContext] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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

  const handleFetchLogs = async () => {
    if (!user) return;
    try {
      const data = await apiFetchLogs(user.token);
      setLogs(data);
    } catch (err) {
      console.error("Fetch logs failed", err);
    }
  };

  const handleFetchUsers = async () => {
    if (!user) return;
    try {
      const data = await apiFetchUsers(user.token);
      setUsers(data);
    } catch (err) {
      console.error("Fetch users failed", err);
    }
  };

  const handleFetchPublicKey = async (username) => {
    if (!user) return;
    try {
      const data = await fetchUserPublicKey(username, user.token);
      if (!data?.publicKey) {
        alert('Failed to fetch recipient public key. Please try again.');
        return;
      }

      const recipientRecord = users.find((u) => u.username === username) 
        || selectedUser 
        || { username };

      setChatContext({
        recipient: recipientRecord,
        publicKeyJwk: data.publicKey
      });
      setShowChat(true);
    } catch (err) {
      console.error('Failed to fetch recipient public key:', err);
      alert('Could not start chat because the recipient key could not be loaded.');
    }
  };

  useEffect(() => {
    if (view === 'dashboard') {
      checkKeyStatus();
      handleFetchLogs();
      handleFetchUsers();
      const interval = setInterval(handleFetchLogs, 5000);
      return () => clearInterval(interval);
    }
  }, [view, user]);

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const rsaKeyPair = await generateKeyPair();
      const rsaPublicKeyJwk = await exportKey(rsaKeyPair.publicKey);

      const ecdsaSigningKeyPair = await customKX_generateLongTermSigningKeyPair();
      const ecdsaPublicKeyJwk = await customKX_exportPublicKeyJwk(ecdsaSigningKeyPair.publicKey);

      await registerUser(formData.username, formData.password, rsaPublicKeyJwk, ecdsaPublicKeyJwk);

      await storePrivateKey(formData.username, rsaKeyPair.privateKey);
      
      await storeSigningPrivateKey(formData.username, ecdsaSigningKeyPair.privateKey);

      localStorage.setItem(`${formData.username}_signing_pub_jwk`, JSON.stringify(ecdsaPublicKeyJwk));

      setView('login');
      alert("Registration successful! Keys stored securely.");

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
      const data = await loginUser(formData.username, formData.password);

      const userData = { username: formData.username, token: data.token };
      
      localStorage.setItem('secure_user_session', JSON.stringify(userData));
      
      setUser(userData);
      
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
    if (user) {
      logSecurityEvent("AUTH_LOGOUT", "User logged out manually", user.token);
    }
    
    localStorage.removeItem('secure_user_session');
    
    setUser(null);
    setChatContext(null);
    setView('login');
    setFormData({ username: '', password: '' });
  };

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
          onShowReplayDemo={() => setView('replay-demo')}
          onShowMitmDemo={() => {
            if (!user) return;
            setMitmContext({
              victim: user.username,
              attacker: selectedUser?.username || 'Any Registered User',
              token: user.token
            });
            setView('mitm-demo');
          }}
        />
      )}

      {view === 'replay-demo' && (
        <div className="fixed inset-0 bg-black bg-opacity-75 z-50 overflow-y-auto">
          <div className="relative">
            <button
              onClick={() => setView('dashboard')}
              className="fixed top-4 right-4 px-4 py-2 bg-white text-black rounded-lg font-semibold hover:bg-gray-100 z-50"
            >
              Back to Dashboard
            </button>
            <ReplayAttackDemo />
          </div>
        </div>
      )}

      {view === 'mitm-demo' && mitmContext && (
        <MitmAttackDemo 
          context={mitmContext}
          onClose={() => {
            setMitmContext(null);
            setView('dashboard');
          }} 
        />
      )}
  
      {showChat && chatContext && (
        <ChatWindow 
          user={user}
          recipient={chatContext.recipient}
          recipientPublicKeyJwk={chatContext.publicKeyJwk}
          onClose={() => {
            setShowChat(false);
            setChatContext(null);
          }}
        />
      )}
    </div>
  );
}