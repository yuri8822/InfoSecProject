import React, { useMemo, useState } from 'react';
import {
  ShieldAlert,
  UserCheck,
  Activity,
  Lock,
  AlertTriangle,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import {
  customKX_generateEphemeralKeyPair,
  customKX_generateLongTermSigningKeyPair,
  customKX_exportPublicKeyJwk,
  customKX_importPublicKeyJwk,
  customKX_signData,
  customKX_verifySignature,
  customKX_buildTranscript,
  customKX_deriveSharedSecret,
  customKX_hkdfDeriveSessionKeys,
  base64ToArrayBuffer,
  encryptAES,
  decryptAES
} from '../utils/crypto';
import { logSecurityEvent } from '../utils/api';

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const logEntry = (setLogs, message) => {
  setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), message }]);
};

export default function MitmAttackDemo({ onClose, context }) {
  const sessionUser = useMemo(() => {
    try {
      const stored = localStorage.getItem('secure_user_session');
      return stored ? JSON.parse(stored) : null;
    } catch (err) {
      console.warn('Failed to parse stored session for MITM demo:', err);
      return null;
    }
  }, []);

  const [insecureLogs, setInsecureLogs] = useState([]);
  const [secureLogs, setSecureLogs] = useState([]);
  const [insecureStatus, setInsecureStatus] = useState('idle');
  const [secureStatus, setSecureStatus] = useState('idle');
    
  const victim = sessionUser?.username || context?.victim || 'Alice';
  const attackerName = context?.attacker || 'Any Registered User';
  const attackerLabel = 'Attacker';
  const token = sessionUser?.token || context?.token || null;
  const pretendPeer = 'SecureChatPeer';

  const runInsecureAttack = async () => {
    setInsecureStatus('running');
    setInsecureLogs([]);

    try {
      logEntry(setInsecureLogs, `${victim} and ${pretendPeer} start Diffie-Hellman WITHOUT signatures.`);
      await delay(300);
      const alice = await customKX_generateEphemeralKeyPair();
      const bob = await customKX_generateEphemeralKeyPair();
      const mallory = await customKX_generateEphemeralKeyPair();

      logEntry(setInsecureLogs, `${attackerLabel} inserts themself as a malicious relay and swaps both public keys.`);
      await delay(300);

      const aliceShared = await customKX_deriveSharedSecret(alice.privateKey, mallory.publicKey);
      const malloryWithAlice = await customKX_deriveSharedSecret(mallory.privateKey, alice.publicKey);
      const bobShared = await customKX_deriveSharedSecret(bob.privateKey, mallory.publicKey);
      const malloryWithBob = await customKX_deriveSharedSecret(mallory.privateKey, bob.publicKey);

      const aliceSession = await customKX_hkdfDeriveSessionKeys(aliceShared);
      const mallorySessionAlice = await customKX_hkdfDeriveSessionKeys(malloryWithAlice, base64ToArrayBuffer(aliceSession.salt));
      const bobSession = await customKX_hkdfDeriveSessionKeys(bobShared);
      const mallorySessionBob = await customKX_hkdfDeriveSessionKeys(malloryWithBob, base64ToArrayBuffer(bobSession.salt));

      logEntry(setInsecureLogs, `${victim} and the ${attackerLabel} now share the EXACT same AES key.`);
      await delay(300);

      const message = 'Attack at dawn';
      const encrypted = await encryptAES(message, aliceSession.aesKey);
      logEntry(setInsecureLogs, `${victim} encrypts a secret order intended for ${pretendPeer}.`);
      await delay(300);

      const malloryPlaintext = await decryptAES(encrypted.ciphertext, encrypted.iv, encrypted.authTag, mallorySessionAlice.aesKey);
      logEntry(setInsecureLogs, `The ${attackerLabel} decrypts the message: "${malloryPlaintext}"`);
      await delay(300);

      const reEncrypted = await encryptAES(malloryPlaintext, mallorySessionBob.aesKey);
      const bobPlaintext = await decryptAES(reEncrypted.ciphertext, reEncrypted.iv, reEncrypted.authTag, bobSession.aesKey);
      logEntry(setInsecureLogs, `The ${attackerLabel} re-encrypts and forwards it. ${pretendPeer} still reads: "${bobPlaintext}"`);
      await delay(300);

      logEntry(setInsecureLogs, `RESULT: The ${attackerLabel} successfully performed a MITM attack on ${victim} because authenticity was missing.`);
      setInsecureStatus('success');
    } catch (err) {
      console.error('MITM insecure demo failed:', err);
      logEntry(setInsecureLogs, `Error: ${err.message}`);
      setInsecureStatus('error');
    }
  };

  const runSignedDefense = async () => {
    setSecureStatus('running');
    setSecureLogs([]);

    try {
      logEntry(setSecureLogs, `${victim} now performs the signed ECDH handshake from our system before messaging ${pretendPeer}.`);
      await delay(300);

      const aliceSigner = await customKX_generateLongTermSigningKeyPair();
      const bobVerifierKey = await customKX_exportPublicKeyJwk(aliceSigner.publicKey);
      const bobVerifier = await customKX_importPublicKeyJwk(bobVerifierKey, 'ecdsa');

      const aliceEphemeral = await customKX_generateEphemeralKeyPair();
      const malloryEphemeral = await customKX_generateEphemeralKeyPair();

      const aliceHello = {
        id: 'Alice',
        ephPub: await customKX_exportPublicKeyJwk(aliceEphemeral.publicKey),
        longTermPub: bobVerifierKey,
        nonce: 'alice-nonce'
      };

      const helloTranscript = customKX_buildTranscript(aliceHello);
      const aliceSignature = await customKX_signData(aliceSigner.privateKey, helloTranscript);
      logEntry(setSecureLogs, `${victim} signs the handshake with their long-term key stored on this device.`);
      await delay(300);

      const tamperedHello = {
        ...aliceHello,
        ephPub: await customKX_exportPublicKeyJwk(malloryEphemeral.publicKey)
      };
      const tamperedTranscript = customKX_buildTranscript(tamperedHello);

      logEntry(setSecureLogs, `The ${attackerLabel} swaps the key but cannot forge ${victim}'s signature.`);
      await delay(300);

      const signatureValid = await customKX_verifySignature(bobVerifier, tamperedTranscript, aliceSignature);
      if (!signatureValid) {
        logEntry(setSecureLogs, `${pretendPeer} verifies the signature → FAILS. Handshake is aborted and MITM is detected.`);
        if (token) {
          await logSecurityEvent(
            'MITM_ATTACK_DETECTED',
            `${victim} detected a MITM attempt from registered user ${attackerName} because signature verification failed.`,
            token
          );
        }
      } else {
        logEntry(setSecureLogs, 'Unexpected: tampering not detected!');
      }

      const legitValid = await customKX_verifySignature(bobVerifier, helloTranscript, aliceSignature);
      logEntry(setSecureLogs, `When the message is untouched, verification passes: ${legitValid ? 'YES' : 'NO'}.`);

      logEntry(setSecureLogs, `RESULT: Digital signatures force ${pretendPeer} to reject the ${attackerLabel}'s tampered handshake, protecting ${victim}.`);
      setSecureStatus('success');
    } catch (err) {
      console.error('MITM signed demo failed:', err);
      logEntry(setSecureLogs, `Error: ${err.message}`);
      setSecureStatus('error');
    }
  };

  const statusBadge = (status) => {
    switch (status) {
      case 'running':
        return <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-600 rounded-full flex items-center gap-1"><Activity size={12} /> Running</span>;
      case 'success':
        return <span className="px-2 py-0.5 text-xs bg-green-100 text-green-600 rounded-full flex items-center gap-1"><ShieldCheck size={12} /> Complete</span>;
      case 'error':
        return <span className="px-2 py-0.5 text-xs bg-red-100 text-red-600 rounded-full flex items-center gap-1"><AlertTriangle size={12} /> Error</span>;
      default:
        return <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-500 rounded-full">Idle</span>;
    }
  };

  const renderLogs = (logs) => (
    <div className="bg-slate-900 text-slate-200 rounded-lg p-4 h-64 overflow-y-auto text-sm space-y-2 font-mono">
      {logs.length === 0 ? (
        <div className="text-slate-500 text-center">No logs yet. Click run to start the simulation.</div>
      ) : (
        logs.map((log, idx) => (
          <div key={idx} className="flex gap-2">
            <span className="text-slate-500">{log.time}</span>
            <span>{log.message}</span>
          </div>
        ))
      )}
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black bg-opacity-80 z-50 overflow-y-auto p-6 flex items-center justify-center">
      <div className="bg-white rounded-2xl shadow-2xl max-w-5xl w-full space-y-6 p-6 border border-gray-100 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 px-4 py-1.5 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200"
        >
          Close
        </button>

        <header className="space-y-2">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-red-500" size={32} />
            <div>
              <h2 className="text-2xl font-bold text-gray-900">MITM Attack Demonstration</h2>
              <p className="text-sm text-gray-600">
                Shows why unauthenticated Diffie-Hellman is vulnerable and how our signed ECDH protocol blocks the attack.
              </p>
            </div>
          </div>
        </header>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-5 border border-red-100 rounded-xl bg-red-50/60 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                <AlertTriangle className="text-red-500" />
                Insecure DH (No Signatures)
              </h3>
              {statusBadge(insecureStatus)}
            </div>
            <p className="text-sm text-gray-700">
              The {attackerLabel} swaps the public keys, derives both shared secrets, decrypts {victim}'s message,
              and re-encrypts it so {pretendPeer} never notices.
            </p>
            <button
              onClick={runInsecureAttack}
              disabled={insecureStatus === 'running'}
              className="w-full flex items-center justify-center gap-2 bg-red-500 hover:bg-red-600 text-white rounded-lg py-2 disabled:opacity-50"
            >
              <RefreshCw size={16} className={insecureStatus === 'running' ? 'animate-spin' : ''} />
              Run MITM Attack
            </button>
            {renderLogs(insecureLogs)}
          </div>

          <div className="p-5 border border-green-100 rounded-xl bg-green-50/60 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-gray-900 flex items-center gap-2">
                <UserCheck className="text-green-600" />
                Signed ECDH (Our System)
              </h3>
              {statusBadge(secureStatus)}
            </div>
            <p className="text-sm text-gray-700">
              {victim} signs the handshake. The {attackerLabel} cannot forge the signature, so {pretendPeer} detects tampering and aborts.
            </p>
            <button
              onClick={runSignedDefense}
              disabled={secureStatus === 'running'}
              className="w-full flex items-center justify-center gap-2 bg-green-600 hover:bg-green-700 text-white rounded-lg py-2 disabled:opacity-50"
            >
              <Lock size={16} />
              Run Defense Simulation
            </button>
            {renderLogs(secureLogs)}
          </div>
        </section>
      </div>
    </div>
  );
}

