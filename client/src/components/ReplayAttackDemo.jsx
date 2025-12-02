/**
 * Replay Attack Protection Demonstration
 * Shows how the system detects and prevents replay attacks
 * 
 * Attack Vector 1: Network Interception - Attacker captures a valid encrypted message and replays it
 * Attack Vector 2: Sequence Number Abuse - Attacker tries to send message with decremented sequence number
 * Attack Vector 3: Timestamp Manipulation - Attacker modifies the message timestamp
 * 
 * Protection Mechanisms:
 * 1. Nonces (One-time Numbers): Each message gets a unique random nonce (16 bytes, 128 bits)
 * 2. Sequence Numbers: Counter increments with each message from sender to receiver
 * 3. Timestamps: Message must be within 5 minutes of server time
 * 4. Duplicate Detection: Server checks if nonce already exists for sender->receiver pair
 */

import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, Copy, Play, Trash2, RefreshCw, Eye, EyeOff } from 'lucide-react';

export default function ReplayAttackDemo() {
  const [attacks, setAttacks] = useState([]);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState('');
  const [serverLogs, setServerLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);
  const [authError, setAuthError] = useState('');

  // Mock user for testing
  const mockUser = {
    username: 'alice',
    password: 'password123'
  };

  // Authenticate and get token
  const authenticate = async () => {
    try {
      console.log('🔐 Authenticating user...');
      const response = await fetch('http://localhost:5000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: mockUser.username,
          password: mockUser.password
        })
      });

      if (response.ok) {
        const data = await response.json();
        console.log('✅ Authentication successful, token:', data.token.substring(0, 20) + '...');
        setToken(data.token);
        localStorage.setItem('token', data.token);
        setAuthError('');
        return data.token;
      } else {
        const error = await response.text();
        console.error('❌ Authentication failed:', error);
        setAuthError('Authentication failed - user does not exist');
        // Try to register
        return await registerAndAuth();
      }
    } catch (err) {
      console.error('❌ Auth error:', err);
      setAuthError('Authentication error: ' + err.message);
      return null;
    }
  };

  // Register user if doesn't exist
  const registerAndAuth = async () => {
    try {
      console.log('📝 Registering new user...');
      // Generate a dummy public key for registration
      const dummyPublicKey = {
        kty: 'RSA',
        e: 'AQAB',
        n: 'dummy_n_value',
        alg: 'RSA-OAEP'
      };

      const registerResponse = await fetch('http://localhost:5000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: mockUser.username,
          password: mockUser.password,
          publicKey: dummyPublicKey
        })
      });

      if (registerResponse.ok) {
        console.log('✅ User registered successfully');
        // Now try to login
        return await authenticate();
      } else {
        const error = await registerResponse.text();
        console.error('❌ Registration failed:', error);
        setAuthError('Registration failed');
        return null;
      }
    } catch (err) {
      console.error('❌ Registration error:', err);
      setAuthError('Registration error: ' + err.message);
      return null;
    }
  };

  // Fetch server logs
  const fetchServerLogs = async (authToken) => {
    setLogsLoading(true);
    try {
      const tokenToUse = authToken || token;
      if (!tokenToUse) {
        console.log('⏭️ Skipping logs fetch - no token yet');
        setLogsLoading(false);
        return;
      }

      const response = await fetch('http://localhost:5000/api/logs', {
        headers: { 'Authorization': `Bearer ${tokenToUse}` }
      });
      if (response.ok) {
        const logs = await response.json();
        console.log('📊 Fetched all logs:', logs);
        
        // Show all logs related to messages, attacks, and auth
        const relevantLogs = logs.filter(log => 
          log.type === 'REPLAY_ATTACK_DETECTED' || 
          log.type === 'MESSAGE_SENT' ||
          log.type === 'AUTH_SUCCESS' ||
          log.type === 'AUTH_FAIL' ||
          log.type === 'KEY_FETCH_SUCCESS'
        ).slice(0, 30); // Get last 30 relevant logs
        
        console.log('🔍 Filtered logs:', relevantLogs);
        setServerLogs(relevantLogs);
      } else {
        console.error('❌ Response not OK:', response.status, response.statusText);
        const errorText = await response.text();
        console.error('Error body:', errorText);
      }
    } catch (err) {
      console.error('❌ Failed to fetch logs:', err);
    } finally {
      setLogsLoading(false);
    }
  };

  // Auto-fetch logs when demo opens - first authenticate
  useEffect(() => {
    let interval;
    
    const initAuth = async () => {
      try {
        // Check if token already exists
        const existingToken = localStorage.getItem('token');
        if (existingToken) {
          console.log('📌 Using existing token from localStorage');
          setToken(existingToken);
          fetchServerLogs(existingToken);
          
          // Start refresh interval
          interval = setInterval(() => {
            fetchServerLogs(existingToken);
          }, 2000);
        } else {
          console.log('🔑 No token found, authenticating...');
          const newToken = await authenticate();
          if (newToken) {
            console.log('✅ Authentication successful, starting log fetch...');
            fetchServerLogs(newToken);
            
            // Start refresh interval
            interval = setInterval(() => {
              fetchServerLogs(newToken);
            }, 2000);
          } else {
            console.error('❌ Failed to authenticate');
          }
        }
      } catch (err) {
        console.error('❌ Error in auth init:', err);
      }
    };

    initAuth();

    return () => {
      if (interval) clearInterval(interval);
    };
  }, []);

  /**
   * ATTACK 1: DUPLICATE NONCE REPLAY
   * Attacker intercepts a message and replays it with the same nonce
   */
  const demonstrateDuplicateNonceAttack = async () => {
    setLoading(true);
    try {
      // Step 1: Send a legitimate message
      const legitNonce = generateRandomNonce();
      const legitSeqNum = Math.floor(Math.random() * 1000);
      
      const legitMessage = {
        to: 'bob',
        encryptedSessionKey: 'mock_key_' + Math.random().toString(36).substring(7),
        ciphertext: 'mock_ciphertext_' + Math.random().toString(36).substring(7),
        iv: 'mock_iv_' + Math.random().toString(36).substring(7),
        authTag: 'mock_tag_' + Math.random().toString(36).substring(7),
        nonce: legitNonce,
        sequenceNumber: legitSeqNum,
        timestamp: new Date().toISOString()
      };

      console.log('📤 Sending legitimate message:', {
        nonce: legitNonce.substring(0, 16) + '...',
        sequenceNumber: legitSeqNum
      });

      const response1 = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(legitMessage)
      });

      const result1 = await response1.json();
      console.log('✅ Legitimate message sent:', result1);

      // Step 2: Attacker captures and replays the SAME message
      console.log('\n🚨 ATTACK: Replaying intercepted message with SAME nonce...');
      
      const replayMessage = {
        to: 'bob',
        encryptedSessionKey: 'mock_key_' + Math.random().toString(36).substring(7),
        ciphertext: 'mock_ciphertext_' + Math.random().toString(36).substring(7),
        iv: 'mock_iv_' + Math.random().toString(36).substring(7),
        authTag: 'mock_tag_' + Math.random().toString(36).substring(7),
        nonce: legitNonce, // SAME NONCE - THIS IS THE ATTACK
        sequenceNumber: legitSeqNum + 1, // Increment sequence to bypass sequence check
        timestamp: new Date().toISOString()
      };
      
      const replayResponse = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(replayMessage)
      });

      const replayResult = await replayResponse.json();
      console.log('❌ Replay attempt result:', replayResult);

      const attack = {
        id: Date.now(),
        type: 'Duplicate Nonce',
        description: 'Attacker captures and replays message with identical nonce',
        legitimate: { status: response1.status, message: result1 },
        attack: { status: replayResponse.status, message: replayResult },
        protection: 'Nonce Uniqueness Check',
        result: replayResponse.status === 400 ? '✅ BLOCKED' : '❌ FAILED'
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * ATTACK 2: SEQUENCE NUMBER MANIPULATION
   * Attacker tries to send a message with a decremented sequence number
   */
  const demonstrateSequenceNumberAttack = async () => {
    setLoading(true);
    try {
      const targetSeq = 100;

      // First send a message with high sequence number to CHARLIE (different recipient)
      const message1 = {
        to: 'charlie',
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: 'ct_' + Math.random().toString(36).substring(7),
        iv: 'iv_' + Math.random().toString(36).substring(7),
        authTag: 'tag_' + Math.random().toString(36).substring(7),
        nonce: generateRandomNonce(),
        sequenceNumber: targetSeq + 10, // Higher sequence
        timestamp: new Date().toISOString()
      };

      const resp1 = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(message1)
      });

      console.log('✅ Legitimate message with seq', targetSeq + 10, ':', resp1.status);

      // Now try to replay with LOWER sequence number
      console.log('🚨 ATTACK: Sending message with LOWER sequence number:', targetSeq);
      
      const message2 = {
        to: 'charlie',
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: 'ct_' + Math.random().toString(36).substring(7),
        iv: 'iv_' + Math.random().toString(36).substring(7),
        authTag: 'tag_' + Math.random().toString(36).substring(7),
        nonce: generateRandomNonce(),
        sequenceNumber: targetSeq, // LOWER sequence
        timestamp: new Date().toISOString()
      };

      const resp2 = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(message2)
      });

      const result2 = await resp2.json();

      const attack = {
        id: Date.now() + 1,
        type: 'Sequence Number Regression',
        description: 'Attacker sends message with sequence number lower than previous',
        legitimate: { seqNum: targetSeq + 10, status: resp1.status },
        attack: { seqNum: targetSeq, status: resp2.status, message: result2 },
        protection: 'Sequence Number Validation',
        result: resp2.status === 400 ? '✅ BLOCKED' : '❌ FAILED'
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * ATTACK 3: TIMESTAMP MANIPULATION
   * Attacker modifies message timestamp to be very old
   */
  const demonstrateTimestampAttack = async () => {
    setLoading(true);
    try {
      // Create message with timestamp 10 minutes old (exceeds 5-minute window)
      const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();

      console.log('🚨 ATTACK: Sending message with timestamp 10 minutes old');

      const message = {
        to: 'diana',
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: 'ct_' + Math.random().toString(36).substring(7),
        iv: 'iv_' + Math.random().toString(36).substring(7),
        authTag: 'tag_' + Math.random().toString(36).substring(7),
        nonce: generateRandomNonce(),
        sequenceNumber: Math.floor(Math.random() * 10000),
        timestamp: oldTimestamp
      };

      const response = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(message)
      });

      const result = await response.json();

      const attack = {
        id: Date.now() + 2,
        type: 'Timestamp Manipulation',
        description: 'Attacker sends message with timestamp older than 5 minutes',
        details: {
          messageTimestamp: oldTimestamp,
          ageMinutes: 10,
          maxAllowedMinutes: 5
        },
        result: response.status === 400 ? '✅ BLOCKED' : '❌ FAILED',
        protection: 'Timestamp Freshness Check',
        message: result
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * ATTACK 4: SAME SEQUENCE WITH DIFFERENT NONCE
   * Attacker tries to send different payload with same sequence but different nonce
   */
  const demonstrateSameSequenceDifferentNonce = async () => {
    setLoading(true);
    try {
      const sharedSeq = Math.floor(Math.random() * 5000) + 100;

      // Send first message to EVE
      const msg1 = {
        to: 'eve',
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: 'ORIGINAL_MESSAGE',
        iv: 'iv_' + Math.random().toString(36).substring(7),
        authTag: 'tag_' + Math.random().toString(36).substring(7),
        nonce: generateRandomNonce(),
        sequenceNumber: sharedSeq,
        timestamp: new Date().toISOString()
      };

      const resp1 = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(msg1)
      });

      console.log('✅ Message accepted with seq', sharedSeq);

      // Try to send different message with same sequence (but different nonce)
      console.log('🚨 ATTACK: Sending DIFFERENT message with SAME sequence number');

      const msg2 = {
        to: 'bob',
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: 'MALICIOUS_MESSAGE', // DIFFERENT content
        iv: 'iv_' + Math.random().toString(36).substring(7),
        authTag: 'tag_' + Math.random().toString(36).substring(7),
        nonce: generateRandomNonce(),
        sequenceNumber: sharedSeq, // SAME sequence
        timestamp: new Date().toISOString()
      };

      const resp2 = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(msg2)
      });

      const result2 = await resp2.json();

      const attack = {
        id: Date.now() + 3,
        type: 'Same Sequence, Different Nonce',
        description: 'Attacker sends malicious message with same sequence number as legitimate message',
        legitimate: { ciphertext: 'ORIGINAL_MESSAGE', seq: sharedSeq },
        attack: { ciphertext: 'MALICIOUS_MESSAGE', seq: sharedSeq },
        protection: 'Sequence Number + Nonce Combination',
        result: resp2.status === 400 ? '✅ BLOCKED' : '❌ FAILED',
        message: result2
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  const generateRandomNonce = () => {
    const nonce = window.crypto.getRandomValues(new Uint8Array(16));
    return btoa(String.fromCharCode(...nonce));
  };

  const clearAttacks = () => {
    setAttacks([]);
    setSelectedAttack(null);
  };

  return (
    <div className="p-6 bg-gray-900 text-white min-h-screen">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
            <AlertTriangle className="text-red-500" size={32} />
            Replay Attack Protection Demo
          </h1>
          <p className="text-gray-400">
            Demonstrates how the system prevents replay attacks using nonces, sequence numbers, and timestamps
          </p>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Attack Controls */}
          <div className="lg:col-span-2">
            {/* Attack Buttons */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
          <button
            onClick={demonstrateDuplicateNonceAttack}
            disabled={loading}
            className="p-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition"
          >
            <Play size={20} />
            Attack 1: Duplicate Nonce Replay
          </button>

          <button
            onClick={demonstrateSequenceNumberAttack}
            disabled={loading}
            className="p-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition"
          >
            <Play size={20} />
            Attack 2: Sequence Number Abuse
          </button>

          <button
            onClick={demonstrateTimestampAttack}
            disabled={loading}
            className="p-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition"
          >
            <Play size={20} />
            Attack 3: Timestamp Manipulation
          </button>

          <button
            onClick={demonstrateSameSequenceDifferentNonce}
            disabled={loading}
            className="p-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition"
          >
            <Play size={20} />
            Attack 4: Sequence Collision
          </button>
        </div>

        {/* Clear Button */}
        {attacks.length > 0 && (
          <button
            onClick={clearAttacks}
            className="mb-6 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg flex items-center gap-2"
          >
            <Trash2 size={18} />
            Clear Results
          </button>
        )}

        {/* Results */}
        <div className="space-y-4">
          {attacks.map((attack, idx) => (
            <div
              key={attack.id}
              className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden cursor-pointer hover:border-gray-600 transition"
              onClick={() => setSelectedAttack(selectedAttack === attack.id ? null : attack.id)}
            >
              {/* Summary */}
              <div className="p-4 flex items-center justify-between bg-gray-750">
                <div className="flex-1">
                  <h3 className="text-lg font-bold mb-1">{attack.type}</h3>
                  <p className="text-sm text-gray-400">{attack.description}</p>
                </div>
                <div className={`px-4 py-2 rounded font-bold ${
                  attack.result === '✅ BLOCKED'
                    ? 'bg-green-900 text-green-300'
                    : 'bg-red-900 text-red-300'
                }`}>
                  {attack.result}
                </div>
              </div>

              {/* Details */}
              {selectedAttack === attack.id && (
                <div className="p-4 bg-gray-900 border-t border-gray-700 space-y-4">
                  <div>
                    <h4 className="font-bold mb-2 text-blue-300">Protection Mechanism:</h4>
                    <p className="text-sm bg-blue-900 bg-opacity-30 p-2 rounded border border-blue-700">
                      {attack.protection}
                    </p>
                  </div>

                  {attack.legitimate && (
                    <div>
                      <h4 className="font-bold mb-2 text-green-300 flex items-center gap-2">
                        <CheckCircle size={18} />
                        Legitimate Message
                      </h4>
                      <pre className="bg-black p-3 rounded text-xs overflow-x-auto max-h-32">
                        {JSON.stringify(attack.legitimate, null, 2)}
                      </pre>
                    </div>
                  )}

                  {attack.attack && (
                    <div>
                      <h4 className="font-bold mb-2 text-red-300 flex items-center gap-2">
                        <AlertTriangle size={18} />
                        Attack Attempt
                      </h4>
                      <pre className="bg-black p-3 rounded text-xs overflow-x-auto max-h-32">
                        {JSON.stringify(attack.attack, null, 2)}
                      </pre>
                    </div>
                  )}

                  {attack.details && (
                    <div>
                      <h4 className="font-bold mb-2 text-yellow-300">Attack Details:</h4>
                      <pre className="bg-black p-3 rounded text-xs overflow-x-auto max-h-32">
                        {JSON.stringify(attack.details, null, 2)}
                      </pre>
                    </div>
                  )}

                  {attack.message && (
                    <div>
                      <h4 className="font-bold mb-2 text-yellow-300">Server Response:</h4>
                      <pre className="bg-black p-3 rounded text-xs overflow-x-auto max-h-32">
                        {JSON.stringify(attack.message, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {attacks.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            <AlertTriangle size={48} className="mx-auto mb-4 opacity-50" />
            <p>Click an attack button above to demonstrate replay attack protection</p>
          </div>
        )}
            </div>

          {/* Right: Server Logs Panel */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden sticky top-6">
              {/* Logs Header */}
              <div className="bg-gray-750 p-4 border-b border-gray-700 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowLogs(!showLogs)}
                    className="text-blue-400 hover:text-blue-300 transition"
                    title={showLogs ? 'Hide logs' : 'Show logs'}
                  >
                    {showLogs ? <Eye size={20} /> : <EyeOff size={20} />}
                  </button>
                  <h3 className="font-bold text-lg">Server Logs</h3>
                </div>
                <button
                  onClick={fetchServerLogs}
                  disabled={logsLoading}
                  className="text-gray-400 hover:text-gray-300 disabled:text-gray-600 transition"
                  title="Refresh logs"
                >
                  <RefreshCw size={18} className={logsLoading ? 'animate-spin' : ''} />
                </button>
              </div>

              {/* Logs Content */}
              {showLogs && (
                <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
                  {serverLogs.length === 0 ? (
                    <p className="text-gray-500 text-sm italic">No logs yet. Run an attack to see logs.</p>
                  ) : (
                    serverLogs.map((log, idx) => {
                      const isAttack = log.type === 'REPLAY_ATTACK_DETECTED';
                      const isAuth = log.type.includes('AUTH');
                      const isKeyFetch = log.type.includes('KEY_FETCH');
                      
                      return (
                      <div
                        key={idx}
                        className={`p-3 rounded border text-xs transition ${
                          isAttack
                            ? 'bg-red-900 bg-opacity-30 border-red-700 hover:border-red-600'
                            : isAuth
                            ? 'bg-blue-900 bg-opacity-30 border-blue-700 hover:border-blue-600'
                            : isKeyFetch
                            ? 'bg-purple-900 bg-opacity-30 border-purple-700 hover:border-purple-600'
                            : 'bg-green-900 bg-opacity-30 border-green-700 hover:border-green-600'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <span className={`font-bold flex items-center gap-1 ${
                            isAttack
                              ? 'text-red-300'
                              : isAuth
                              ? 'text-blue-300'
                              : isKeyFetch
                              ? 'text-purple-300'
                              : 'text-green-300'
                          }`}>
                            {isAttack ? '🚨' : isAuth ? '🔐' : isKeyFetch ? '🔑' : '✅'} {log.type}
                          </span>
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded whitespace-nowrap ${
                            log.severity === 'critical'
                              ? 'bg-red-600 text-white'
                              : log.severity === 'warning'
                              ? 'bg-yellow-600 text-white'
                              : 'bg-green-600 text-white'
                          }`}>
                            {log.severity?.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-gray-300 mb-2 line-clamp-2">{log.details}</p>
                        <div className="text-gray-400 space-y-0.5 text-xs">
                          <p>👤 {log.username || 'system'}</p>
                          <p>🕐 {new Date(log.timestamp).toLocaleTimeString()}</p>
                          {log.ipAddress && <p>🌐 {log.ipAddress}</p>}
                        </div>
                      </div>
                    );
                    })
                  )}
                </div>
              )}
              {!showLogs && (
                <div className="p-4 text-center text-gray-500 text-sm h-96 flex items-center justify-center">
                  Click eye icon to view logs
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
