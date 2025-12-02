/**
 * MITM (Man-in-the-Middle) Attack Demonstration
 * Shows how MITM breaks Diffie-Hellman without signatures
 * Shows how digital signatures prevent MITM attacks
 * 
 * Attack Vector 1: MITM without digital signatures
 * - Attacker intercepts DH exchange between Alice and Bob
 * - Establishes separate keys with each party
 * - Sits in the middle decrypting and re-encrypting messages
 * 
 * Protection: Digital signatures verify message authenticity
 * - Each party signs their public key with their private key
 * - Receiver verifies signature using sender's public key
 * - Prevents attacker from impersonating either party
 */

import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, AlertCircle, Play, RefreshCw, Eye, EyeOff } from 'lucide-react';

export default function MITMDemo({ currentUser }) {
  const [attacks, setAttacks] = useState([]);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading, setLoading] = useState(false);
  const [serverLogs, setServerLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const [logsLoading, setLogsLoading] = useState(false);

  // Mock DH parameters (simplified for demo)
  const dhParams = {
    p: 23, // Prime number
    g: 5   // Generator
  };

  // Fetch server logs (silently fail if not available)
  const fetchServerLogs = async () => {
    setLogsLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setLogsLoading(false);
        return;
      }

      const response = await fetch('http://localhost:5000/api/logs', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const logs = await response.json();
        
        // Filter for MITM-related logs
        const relevantLogs = logs.filter(log => 
          log.type === 'MITM_ATTACK_DETECTED' || 
          log.type === 'MITM_SIGNATURE_VERIFIED' ||
          log.type === 'SIGNATURE_VERIFICATION_FAILED' ||
          log.type === 'DH_KEY_EXCHANGE'
        ).slice(0, 30);
        
        setServerLogs(relevantLogs);
      }
    } catch (err) {
      // Silently handle errors - demo works without server logs
      // Console logs are the primary output for this demo
    } finally {
      setLogsLoading(false);
    }
  };

  // Auto-refresh logs (optional feature)
  useEffect(() => {
    // Only attempt to fetch logs if we have a token
    const token = localStorage.getItem('token');
    if (token) {
      fetchServerLogs();
      const interval = setInterval(fetchServerLogs, 2000);
      return () => clearInterval(interval);
    }
  }, []);

  /**
   * ATTACK 1: MITM WITHOUT DIGITAL SIGNATURES
   * Demonstrates how attacker intercepts DH exchange
   */
  const demonstrateMITMWithoutSignatures = async () => {
    setLoading(true);
    try {
      console.log('🚨 ATTACK 1: MITM WITHOUT DIGITAL SIGNATURES');
      console.log('================================================');

      // Step 1: Alice and Bob agree on DH parameters
      console.log('\n📋 Step 1: Alice and Bob agree on DH parameters');
      console.log(`   p (prime) = ${dhParams.p}`);
      console.log(`   g (generator) = ${dhParams.g}`);

      // Step 2: Alice generates private key and public key
      const alicePrivate = Math.floor(Math.random() * (dhParams.p - 2)) + 2;
      const alicePublic = Math.pow(dhParams.g, alicePrivate) % dhParams.p;

      console.log(`\n👤 Alice:`);
      console.log(`   Private key (secret): ${alicePrivate}`);
      console.log(`   Public key (sent): ${alicePublic}`);

      // Step 3: Attacker (Eve) intercepts Alice's public key
      console.log(`\n🕵️ ATTACKER (Eve) INTERCEPTS Alice's public key: ${alicePublic}`);

      // Step 4: Eve generates her own private key
      const evePrivate = Math.floor(Math.random() * (dhParams.p - 2)) + 2;
      const evePublic = Math.pow(dhParams.g, evePrivate) % dhParams.p;

      // Eve pretends to be Alice to Bob
      console.log(`\n🕵️ Eve creates FAKE public key to send to Bob: ${evePublic}`);
      console.log(`   (Eve claims this is Alice's key - NO SIGNATURE TO VERIFY!)`);

      // Step 5: Bob generates private key
      const bobPrivate = Math.floor(Math.random() * (dhParams.p - 2)) + 2;
      const bobPublic = Math.pow(dhParams.g, bobPrivate) % dhParams.p;

      console.log(`\n👤 Bob:`);
      console.log(`   Private key (secret): ${bobPrivate}`);
      console.log(`   Public key (sent): ${bobPublic}`);

      // Step 6: Eve intercepts Bob's public key
      console.log(`\n🕵️ Eve INTERCEPTS Bob's public key: ${bobPublic}`);

      // Step 7: Compute shared secrets
      // Eve-Alice: Eve computes shared key with Alice using Alice's private... wait, Eve doesn't have it
      // Instead: Eve computes key with Alice's public
      const eveAliceSharedSecret = Math.pow(alicePublic, evePrivate) % dhParams.p;
      
      // Eve-Bob: Eve computes shared key with Bob using Bob's public
      const eveBobSharedSecret = Math.pow(bobPublic, evePrivate) % dhParams.p;

      // Alice computes (expecting Bob but gets Eve)
      const aliceBobSharedSecret = Math.pow(evePublic, alicePrivate) % dhParams.p;

      // Bob computes (expecting Alice but gets Eve)
      const bobAliceSharedSecret = Math.pow(evePublic, bobPrivate) % dhParams.p;

      console.log(`\n🔐 SHARED SECRETS COMPUTED:`);
      console.log(`   Alice thinks shared key with Bob is: ${aliceBobSharedSecret}`);
      console.log(`   Bob thinks shared key with Alice is: ${bobAliceSharedSecret}`);
      console.log(`   Eve has TWO keys:`);
      console.log(`     - Eve-Alice shared secret: ${eveAliceSharedSecret}`);
      console.log(`     - Eve-Bob shared secret: ${eveBobSharedSecret}`);

      console.log(`\n✅ RESULT: Eve is now in the middle!`);
      console.log(`   Alice encrypts with key ${aliceBobSharedSecret} (thinking it's Bob)`);
      console.log(`   Eve decrypts with key ${eveAliceSharedSecret}`);
      console.log(`   Eve re-encrypts with key ${eveBobSharedSecret}`);
      console.log(`   Bob decrypts with key ${bobAliceSharedSecret}`);

      const attack = {
        id: Date.now(),
        type: 'MITM Without Signatures',
        description: 'Attacker intercepts Diffie-Hellman key exchange (NO SIGNATURES)',
        details: {
          vulnerability: 'No digital signatures to verify public keys',
          impact: 'Attacker can decrypt and modify all messages',
          dhParameters: {
            prime: dhParams.p,
            generator: dhParams.g
          },
          keyExchange: {
            alice: {
              privateKey: alicePrivate,
              publicKeySent: alicePublic,
              sharedSecretComputed: aliceBobSharedSecret,
              thinksCommunicatingWith: 'Bob',
              actuallyTalkingTo: 'Eve'
            },
            eve: {
              privateKey: evePrivate,
              sharedSecretWithAlice: eveAliceSharedSecret,
              sharedSecretWithBob: eveBobSharedSecret,
              canDecryptAliceMessages: true,
              canDecryptBobMessages: true
            },
            bob: {
              privateKey: bobPrivate,
              publicKeySent: bobPublic,
              sharedSecretComputed: bobAliceSharedSecret,
              thinksCommunicatingWith: 'Alice',
              actuallyTalkingTo: 'Eve'
            }
          }
        },
        protection: 'NONE - No signatures to verify public key authenticity',
        result: '❌ VULNERABLE - Full MITM achieved'
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * ATTACK 2: MITM PREVENTED BY DIGITAL SIGNATURES
   * Shows how signatures protect against MITM
   */
  const demonstrateMITMWithSignatures = async () => {
    setLoading(true);
    try {
      console.log('\n✅ PROTECTION: MITM PREVENTED BY DIGITAL SIGNATURES');
      console.log('===================================================');

      // Step 1: Alice and Bob agree on parameters
      console.log('\n📋 Step 1: Alice and Bob pre-share trusted public keys');
      console.log('   (via secure channel or certificate authority)');

      // Step 2: Alice creates signed message with her public key
      const alicePrivate = Math.floor(Math.random() * (dhParams.p - 2)) + 2;
      const alicePublic = Math.pow(dhParams.g, alicePrivate) % dhParams.p;
      
      console.log(`\n👤 Alice:`);
      console.log(`   Generates DH public key: ${alicePublic}`);
      console.log(`   SIGNS her public key with her private key (digital signature)`);
      console.log(`   Signature Algorithm: RSA-PSS with SHA-256`);

      const aliceSignature = `SIG_${alicePrivate}_${alicePublic}`;
      console.log(`   Signature: ${aliceSignature.substring(0, 40)}...`);

      // Step 3: Eve tries to intercept and send her key as Alice
      const evePrivate = Math.floor(Math.random() * (dhParams.p - 2)) + 2;
      const evePublic = Math.pow(dhParams.g, evePrivate) % dhParams.p;

      console.log(`\n🕵️ Eve ATTEMPTS MITM:`);
      console.log(`   Intercepts Alice's message with signature`);
      console.log(`   Tries to send her own public key: ${evePublic}`);
      console.log(`   Problem: Eve doesn't have Alice's private key to create valid signature`);

      const eveSignature = `FAKE_${evePrivate}_${evePublic}`;
      console.log(`   Eve's fake signature: ${eveSignature.substring(0, 40)}...`);

      // Step 4: Bob receives and verifies
      console.log(`\n👤 Bob receives the message:`);
      console.log(`   Public key claimed to be from Alice: ???`);
      console.log(`   Signature: ???`);

      console.log(`\n🔍 Bob VERIFIES the signature:`);
      console.log(`   Uses Alice's pre-shared public key to verify signature`);
      console.log(`   Valid Alice signature? YES ✅`);
      console.log(`   Signature matches Alice's key? YES ✅`);

      console.log(`\n🛑 If Eve tries to send her key:`);
      console.log(`   Signature verification FAILS ❌`);
      console.log(`   Signature does NOT match Alice's pre-shared public key`);
      console.log(`   Bob REJECTS the message`);
      console.log(`   MITM ATTACK DETECTED AND BLOCKED!`);

      const attack = {
        id: Date.now() + 1,
        type: 'MITM With Digital Signatures',
        description: 'Digital signatures prevent MITM by verifying key authenticity',
        details: {
          protection: 'Digital signatures on DH public keys',
          signingAlgorithm: 'RSA-PSS with SHA-256',
          keyExchange: {
            alice: {
              privateKey: alicePrivate,
              publicKeySent: alicePublic,
              signature: aliceSignature.substring(0, 40) + '...',
              signatureVerified: true
            },
            eve: {
              attemptedPublicKey: evePublic,
              fakeSignature: eveSignature.substring(0, 40) + '...',
              signatureVerified: false,
              reason: 'Signature does not match Alice\'s public key'
            },
            bob: {
              verification: {
                receivedPublicKey: alicePublic,
                receivedSignature: aliceSignature.substring(0, 40) + '...',
                alicePreSharedPublicKey: alicePublic,
                signatureMatches: true,
                accepts: true
              }
            }
          }
        },
        protection: 'Digital Signatures - Message Authentication Code (MAC)',
        result: '✅ PROTECTED - MITM Attack Blocked'
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
  };

  /**
   * DEMONSTRATION: Show how signatures work
   */
  const demonstrateSignatureVerification = async () => {
    setLoading(true);
    try {
      console.log('\n🔐 HOW DIGITAL SIGNATURES WORK');
      console.log('================================');

      console.log('\n1️⃣ MESSAGE SIGNING (Alice):');
      console.log('   Alice computes hash of her DH public key');
      console.log('   Alice encrypts hash with her PRIVATE key');
      console.log('   This is the SIGNATURE');
      console.log('   Alice sends: [Public Key] + [Signature]');

      console.log('\n2️⃣ SIGNATURE VERIFICATION (Bob):');
      console.log('   Bob receives: [Alice\'s Public Key] + [Signature]');
      console.log('   Bob decrypts signature using Alice\'s PUBLIC key');
      console.log('   Bob computes hash of the received public key');
      console.log('   If hashes match → Signature is VALID ✅');
      console.log('   If hashes don\'t match → Signature is INVALID ❌');

      console.log('\n3️⃣ WHY ATTACKER CAN\'T FORGE SIGNATURE:');
      console.log('   Attacker (Eve) doesn\'t have Alice\'s PRIVATE key');
      console.log('   Eve CAN\'T encrypt with Alice\'s private key');
      console.log('   Eve CAN\'T create valid signature for her fake key');
      console.log('   Bob\'s verification will FAIL');
      console.log('   Attack is DETECTED and BLOCKED');

      const attack = {
        id: Date.now() + 2,
        type: 'Digital Signature Mechanism',
        description: 'How digital signatures authenticate messages',
        details: {
          process: [
            {
              step: 1,
              name: 'Sender Signs',
              action: 'Hash(message) + Encrypt with sender\'s private key = Signature'
            },
            {
              step: 2,
              name: 'Receiver Verifies',
              action: 'Decrypt signature with sender\'s public key = Hash\'',
              verification: 'Compute Hash(received message) and compare with Hash\''
            },
            {
              step: 3,
              name: 'Decision',
              matching: 'Hashes match → AUTHENTIC ✅',
              notMatching: 'Hashes don\'t match → FORGED ❌'
            }
          ],
          security: {
            canForgeWithout: 'Sender\'s private key',
            attacker: 'Only has public keys (which are public)',
            conclusion: 'Cannot create valid signature without private key'
          }
        },
        protection: 'RSA Digital Signatures with SHA-256 hashing',
        result: '✅ SECURE - Sender authenticity guaranteed'
      };

      setAttacks(prev => [attack, ...prev]);
    } catch (err) {
      console.error('Demo error:', err);
    } finally {
      setLoading(false);
    }
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
            MITM (Man-in-the-Middle) Attack Demo
          </h1>
          <p className="text-gray-400">
            Demonstrates how attackers intercept key exchanges and how digital signatures prevent MITM attacks
          </p>

          {/* Status */}
          <div className="mt-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-500">👤 Current User:</p>
                <p className="text-yellow-400 font-bold">{currentUser || 'Loading...'}</p>
              </div>
              <div>
                <p className="text-gray-500">🎯 Attack Target:</p>
                <p className="text-blue-400 font-bold">Diffie-Hellman Key Exchange</p>
              </div>
            </div>
            <p className="text-xs text-gray-600 mt-3">
              ℹ️ This demo shows how attackers intercept unprotected key exchanges and how digital signatures defend against MITM.
            </p>
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Attack Controls */}
          <div className="lg:col-span-2">
            {/* Attack Buttons */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              <button
                onClick={demonstrateMITMWithoutSignatures}
                disabled={loading}
                className="p-4 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition text-sm"
              >
                <Play size={18} />
                Attack 1: MITM No Signatures
              </button>

              <button
                onClick={demonstrateMITMWithSignatures}
                disabled={loading}
                className="p-4 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition text-sm"
              >
                <Play size={18} />
                Attack 2: MITM With Signatures
              </button>

              <button
                onClick={demonstrateSignatureVerification}
                disabled={loading}
                className="p-4 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 rounded-lg font-semibold flex items-center gap-2 transition text-sm"
              >
                <Play size={18} />
                How Signatures Work
              </button>
            </div>

            {/* Clear Button */}
            {attacks.length > 0 && (
              <button
                onClick={clearAttacks}
                className="mb-6 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg flex items-center gap-2 text-sm"
              >
                Clear Results
              </button>
            )}

            {/* Results */}
            <div className="space-y-4">
              {attacks.map((attack) => (
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
                    <div className={`px-4 py-2 rounded font-bold whitespace-nowrap text-xs ${
                      attack.result.includes('PROTECTED') || attack.result.includes('SECURE')
                        ? 'bg-green-900 text-green-300'
                        : attack.result.includes('VULNERABLE')
                        ? 'bg-red-900 text-red-300'
                        : 'bg-yellow-900 text-yellow-300'
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

                      <div>
                        <h4 className="font-bold mb-2 text-yellow-300">Attack Details:</h4>
                        <pre className="bg-black p-3 rounded text-xs overflow-x-auto max-h-64 text-gray-300">
                          {JSON.stringify(attack.details, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {attacks.length === 0 && (
              <div className="text-center py-12 text-gray-500">
                <AlertTriangle size={48} className="mx-auto mb-4 opacity-50" />
                <p>Click an attack button above to demonstrate MITM attacks</p>
              </div>
            )}
          </div>

          {/* Right: Console Logs */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden sticky top-6">
              {/* Logs Header */}
              <div className="bg-gray-750 p-4 border-b border-gray-700 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowLogs(!showLogs)}
                    className="text-blue-400 hover:text-blue-300 transition"
                  >
                    {showLogs ? <Eye size={20} /> : <EyeOff size={20} />}
                  </button>
                  <h3 className="font-bold text-lg">Console Output</h3>
                </div>
                <button
                  onClick={fetchServerLogs}
                  disabled={logsLoading}
                  className="text-gray-400 hover:text-gray-300 disabled:text-gray-600 transition"
                >
                  <RefreshCw size={18} className={logsLoading ? 'animate-spin' : ''} />
                </button>
              </div>

              {/* Logs Content */}
              {showLogs && (
                <div className="p-4 space-y-2 max-h-96 overflow-y-auto bg-black font-mono text-xs">
                  <div className="text-blue-400">
                    <p>{'>'} MITM Attack Demonstration Started</p>
                    <p>{'>'} Check browser console for detailed output</p>
                    <p>{'>'} Open DevTools (F12) to see attack flow</p>
                  </div>
                  <div className="text-gray-500 mt-4">
                    <p>Use Attack buttons to see console logs showing:</p>
                    <p className="text-red-400 mt-2">• How MITM intercepts without signatures</p>
                    <p className="text-green-400">• How signatures prevent MITM</p>
                    <p className="text-yellow-400">• How key verification works</p>
                  </div>
                </div>
              )}
              {!showLogs && (
                <div className="p-4 text-center text-gray-500 text-sm h-96 flex items-center justify-center">
                  Click eye icon to view console logs
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
