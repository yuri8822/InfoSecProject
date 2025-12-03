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
import { generateAESKey, encryptAES, generateNonce, generateKeyPair, exportKey } from '../utils/crypto';

export default function ReplayAttackDemo({ currentUser }) {
  const [attacks, setAttacks] = useState([]);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState('');
  const [serverLogs, setServerLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);
  const [authError, setAuthError] = useState('');
  const [victim, setVictim] = useState(currentUser); // VICTIM IS THE PASSED USER

  // Attacker account used to send replay attacks
  const attackerAccount = {
    username: 'alice',
    password: 'password123'
  };

  // Authenticate and get token
  const authenticate = async () => {
    try {
      console.log('🔐 Authenticating attacker account...');
      const response = await fetch('http://localhost:5000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: attackerAccount.username,
          password: attackerAccount.password
        })
      });

      if (response.ok) {
        const data = await response.json();
        console.log('✅ Attacker authentication successful, token:', data.token.substring(0, 20) + '...');
        setToken(data.token);
        localStorage.setItem('attackToken', data.token);
        setAuthError('');
        return data.token;
      } else {
        const error = await response.text();
        console.error('❌ Authentication failed:', error);
        setAuthError('Authentication failed - attacker account does not exist');
        // Try to register
        return await registerAndAuth();
      }
    } catch (err) {
      console.error('❌ Auth error:', err);
      setAuthError('Authentication error: ' + err.message);
      return null;
    }
  };

  // Register attacker account if doesn't exist
  const registerAndAuth = async () => {
    try {
      console.log('📝 Registering attacker account...');
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
          username: attackerAccount.username,
          password: attackerAccount.password,
          publicKey: dummyPublicKey
        })
      });

      if (registerResponse.ok) {
        console.log('✅ Attacker account registered successfully');
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
        // Use the victim passed from parent component
        if (currentUser) {
          setVictim(currentUser);
          console.log(`👤 Current user (VICTIM): ${currentUser}`);
          console.log(`🔓 Will demonstrate replay attacks targeting: ${currentUser}`);
        }

        // Get or create attacker token
        const existingAttackToken = localStorage.getItem('attackToken');
        if (existingAttackToken) {
          console.log('📌 Using existing attacker token from localStorage');
          setToken(existingAttackToken);
          fetchServerLogs(existingAttackToken);
          
          // Start refresh interval
          interval = setInterval(() => {
            fetchServerLogs(existingAttackToken);
          }, 2000);
        } else {
          console.log('🔑 No attacker token found, authenticating attacker account...');
          const newToken = await authenticate();
          if (newToken) {
            console.log('✅ Attacker authentication successful, starting log fetch...');
            fetchServerLogs(newToken);
            
            // Start refresh interval
            interval = setInterval(() => {
              fetchServerLogs(newToken);
            }, 2000);
          } else {
            console.error('❌ Failed to authenticate attacker account');
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
  }, [currentUser]);

  /**
   * ATTACK 1: DUPLICATE NONCE REPLAY
   * Attacker (alice) intercepts a message and replays it to VICTIM (logged-in user)
   */
  const demonstrateDuplicateNonceAttack = async () => {
    if (!victim) {
      alert('No victim user detected. Please ensure you are logged in.');
      return;
    }
    
    setLoading(true);
    try {
      // Step 1: Generate real encrypted message FROM attacker TO victim
      const legitNonce = generateNonce();
      const legitSeqNum = Math.floor(Math.random() * 1000);
      
      // Create real AES key and encrypt a message
      const aesKey = await generateAESKey();
      const messageContent = `Hello ${victim}! This is a legitimate message from alice.`;
      const encrypted = await encryptAES(messageContent, aesKey);
      
      const legitMessage = {
        to: victim, // VICTIM IS THE RECIPIENT
        encryptedSessionKey: 'mock_key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        nonce: legitNonce,
        sequenceNumber: legitSeqNum,
        timestamp: new Date().toISOString()
      };

      console.log('📤 Attacker sending legitimate message to VICTIM:', {
        victim: victim,
        content: messageContent,
        nonce: legitNonce.substring(0, 16) + '...',
        sequenceNumber: legitSeqNum,
        ciphertext: encrypted.ciphertext.substring(0, 30) + '...'
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
      console.log('✅ Legitimate message sent to victim:', result1);

      // Step 2: Attacker captures and replays the SAME message
      console.log('\n🚨 ATTACK: Replaying intercepted message with SAME nonce to VICTIM...');
      
      const replayMessage = {
        to: victim, // SAME VICTIM
        encryptedSessionKey: 'mock_key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted.ciphertext, // Same ciphertext
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        nonce: legitNonce, // SAME NONCE - THIS IS THE ATTACK
        sequenceNumber: legitSeqNum + 1, // Increment sequence to try to bypass sequence check
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
        type: 'Duplicate Nonce Replay',
        description: `Attacker (alice) replays message to VICTIM (${victim}) with identical nonce`,
        details: {
          attacker: 'alice',
          victim: victim,
          messageContent,
          nonce: legitNonce.substring(0, 20) + '...',
          encryptionDetails: {
            algorithm: 'AES-256-GCM',
            ciphertext: encrypted.ciphertext.substring(0, 50) + '...',
            iv: encrypted.iv.substring(0, 20) + '...',
            authTag: encrypted.authTag.substring(0, 20) + '...'
          }
        },
        legitimate: { status: response1.status, message: result1 },
        attack: { status: replayResponse.status, message: replayResult },
        protection: 'Nonce Uniqueness Check - Server detects duplicate nonce and blocks replay to victim',
        result: replayResponse.status === 400 ? '✅ VICTIM PROTECTED' : '❌ ATTACK SUCCEEDED'
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
   * Attacker (alice) tries to send to VICTIM with decremented sequence number
   */
  const demonstrateSequenceNumberAttack = async () => {
    if (!currentUser) {
      alert('No victim user detected. Please ensure you are logged in.');
      return;
    }

    setLoading(true);
    try {
      const targetSeq = 100;
      
      // Create real encrypted message
      const aesKey = await generateAESKey();
      const messageContent = `Message to ${currentUser} with high sequence number`;
      const encrypted = await encryptAES(messageContent, aesKey);

      // First send a message with high sequence number to VICTIM
      const message1 = {
        to: currentUser, // VICTIM
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        nonce: generateNonce(),
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

      console.log('✅ Legitimate message with seq', targetSeq + 10, 'to victim:', resp1.status);

      // Now try to replay with LOWER sequence number
      console.log('🚨 ATTACK: Sending message with LOWER sequence number to VICTIM');
      
      const aesKey2 = await generateAESKey();
      const maliciousContent = 'Malicious message with lower sequence';
      const encrypted2 = await encryptAES(maliciousContent, aesKey2);
      
      const message2 = {
        to: currentUser, // SAME VICTIM
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted2.ciphertext,
        iv: encrypted2.iv,
        authTag: encrypted2.authTag,
        nonce: generateNonce(),
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
        description: `Attacker (alice) sends message to VICTIM (${currentUser}) with decremented sequence number`,
        details: {
          attacker: 'alice',
          victim: currentUser,
          legitimate: { content: messageContent, sequence: targetSeq + 10 },
          attack: { content: maliciousContent, sequence: targetSeq },
          encryptionDetails: {
            algorithm: 'AES-256-GCM',
            legitimateCiphertext: encrypted.ciphertext.substring(0, 50) + '...',
            maliciousCiphertext: encrypted2.ciphertext.substring(0, 50) + '...'
          }
        },
        legitimate: { seqNum: targetSeq + 10, status: resp1.status },
        attack: { seqNum: targetSeq, status: resp2.status, message: result2 },
        protection: 'Sequence Number Validation - Server enforces monotonically increasing sequences per recipient',
        result: resp2.status === 400 ? '✅ VICTIM PROTECTED' : '❌ ATTACK SUCCEEDED'
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
   * Attacker (alice) sends to VICTIM with an old timestamp
   */
  const demonstrateTimestampAttack = async () => {
    if (!currentUser) {
      alert('No victim user detected. Please ensure you are logged in.');
      return;
    }

    setLoading(true);
    try {
      // Create real encrypted message
      const aesKey = await generateAESKey();
      const messageContent = `Old message from alice to ${currentUser} from 10 minutes ago`;
      const encrypted = await encryptAES(messageContent, aesKey);
      
      // Create message with timestamp 10 minutes old (exceeds 5-minute window)
      const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();

      console.log(`🚨 ATTACK: Sending OLD message (10 min old) to VICTIM (${currentUser})`);

      const message = {
        to: currentUser, // VICTIM
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        nonce: generateNonce(),
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
        description: `Attacker (alice) sends STALE message to VICTIM (${currentUser}) with timestamp older than 5 minutes`,
        details: {
          attacker: 'alice',
          victim: currentUser,
          messageContent,
          messageTimestamp: oldTimestamp,
          currentServerTime: new Date().toISOString(),
          ageMinutes: 10,
          maxAllowedMinutes: 5,
          encryptionDetails: {
            algorithm: 'AES-256-GCM',
            ciphertext: encrypted.ciphertext.substring(0, 50) + '...',
            iv: encrypted.iv.substring(0, 20) + '...',
            authTag: encrypted.authTag.substring(0, 20) + '...'
          }
        },
        result: response.status === 400 ? '✅ VICTIM PROTECTED' : '❌ ATTACK SUCCEEDED',
        protection: 'Timestamp Freshness Check - Server rejects messages older than 5 minutes',
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
   * Attacker (alice) tries to send different payload with same sequence to VICTIM
   */
  const demonstrateSameSequenceDifferentNonce = async () => {
    if (!currentUser) {
      alert('No victim user detected. Please ensure you are logged in.');
      return;
    }

    setLoading(true);
    try {
      const sharedSeq = Math.floor(Math.random() * 5000) + 100;

      // Create first real encrypted message
      const aesKey1 = await generateAESKey();
      const originalContent = 'Original legitimate message to victim';
      const encrypted1 = await encryptAES(originalContent, aesKey1);
      
      // Send first message to VICTIM
      const msg1 = {
        to: currentUser, // VICTIM
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted1.ciphertext,
        iv: encrypted1.iv,
        authTag: encrypted1.authTag,
        nonce: generateNonce(),
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

      console.log(`✅ Message accepted with seq ${sharedSeq} to victim`);

      // Create second malicious encrypted message
      const aesKey2 = await generateAESKey();
      const maliciousContent = 'Malicious message trying to impersonate original';
      const encrypted2 = await encryptAES(maliciousContent, aesKey2);
      
      // Try to send different message with same sequence
      console.log(`🚨 ATTACK: Sending DIFFERENT message with SAME sequence to VICTIM`);

      const msg2 = {
        to: currentUser, // SAME VICTIM
        encryptedSessionKey: 'key_' + Math.random().toString(36).substring(7),
        ciphertext: encrypted2.ciphertext,
        iv: encrypted2.iv,
        authTag: encrypted2.authTag,
        nonce: generateNonce(),
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
        description: `Attacker (alice) sends malicious message to VICTIM (${currentUser}) with same sequence number as legitimate message`,
        details: {
          attacker: 'alice',
          victim: currentUser,
          legitimate: { 
            content: originalContent, 
            sequence: sharedSeq,
            ciphertext: encrypted1.ciphertext.substring(0, 50) + '...'
          },
          attack: { 
            content: maliciousContent, 
            sequence: sharedSeq,
            ciphertext: encrypted2.ciphertext.substring(0, 50) + '...'
          },
          encryptionComparison: {
            legitimateIV: encrypted1.iv.substring(0, 20) + '...',
            attackIV: encrypted2.iv.substring(0, 20) + '...',
            legitimateAuthTag: encrypted1.authTag.substring(0, 20) + '...',
            attackAuthTag: encrypted2.authTag.substring(0, 20) + '...'
          }
        },
        protection: 'Sequence Number + Nonce Combination - Server tracks sequences per recipient independently',
        result: resp2.status === 400 ? '✅ VICTIM PROTECTED' : '❌ ATTACK SUCCEEDED',
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
    return generateNonce();
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
          
          {/* Status - Show Attacker and Victim */}
          <div className="mt-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-500">🔓 Attacker Account:</p>
                <p className="text-red-400 font-bold">alice</p>
              </div>
              <div>
                <p className="text-gray-500">👤 Victim (Current User):</p>
                <p className="text-yellow-400 font-bold">{victim || 'Loading...'}</p>
              </div>
            </div>
            <p className="text-xs text-gray-600 mt-3">
              ℹ️ Alice will attempt replay attacks targeting <strong>{victim || 'the logged-in user'}</strong>. The system will demonstrate how these attacks are blocked.
            </p>
          </div>
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
