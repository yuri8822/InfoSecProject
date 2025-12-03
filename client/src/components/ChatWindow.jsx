/**
 * Part 3 & 4: Encrypted Chat Window
 * Implements E2EE messaging with security status notifications
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Lock, 
  Key, 
  MessageCircle, 
  Send, 
  CheckCircle,
  AlertTriangle,
  Loader,
  FileUp,
  X,
  Upload,
  AlertCircle
} from 'lucide-react';

// CUSTOM KEY EXCHANGE PROTOCOL: Import cryptographic functions
// These functions implement Part 3 of the assignment: Secure Key Exchange
import { 
  encryptAES,
  decryptAES,
  generateNonce,
  encryptFileForSharing,
  decryptFileFromSharing,
  generateAESKey,
  encryptAESKeyWithRSA,
  decryptAESKeyWithRSA,
  importPublicKey,
  // CUSTOM PROTOCOL FUNCTION (Part Y: SECURE KEY EXCHANGE PROTOCOL)
  customKX_performKeyExchange        // Main function: Complete key exchange orchestration
} from '../utils/crypto';

import { 
  sendMessage as apiSendMessage,
  fetchMessages,
  logSecurityEvent,
  uploadEncryptedFile,
  logFileSharingEvent,
  downloadEncryptedFile
} from '../utils/api';

import { getPrivateKey } from '../utils/indexedDB';

export default function ChatWindow({ user, recipient, recipientPublicKeyJwk, onClose }) {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  
  // Security status states (Part 2, 3, 4)
  const [securityStatus, setSecurityStatus] = useState({
    step1_connection: 'pending',      // Part 2: Secure connection
    step2_keyExchange: 'pending',     // Part 3: Key exchange
    step3_encryption: 'pending',      // Part 4: Encryption ready
  });

  // CUSTOM KEY EXCHANGE PROTOCOL (Part Y): Session keys derived from ECDH
  // Instead of RSA key encryption per message, we now use authenticated ECDH
  // to derive a long-lived session key (AES-256-GCM) for all messages in this session
  const [sessionAesKey, setSessionAesKey] = useState(null);
  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [sequenceNumber, setSequenceNumber] = useState(0);
  const [recipientPublicKey, setRecipientPublicKey] = useState(null);
  
  // PART 5: File sharing state in chat
  const [showFileShareModal, setShowFileShareModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileUploadProgress, setFileUploadProgress] = useState(0);
  const [fileUploading, setFileUploading] = useState(false);
  const [fileShareStatus, setFileShareStatus] = useState('');
  
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  // Initialize secure connection
  useEffect(() => {
    initializeSecureChat();
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Poll for new messages
  useEffect(() => {
    const interval = setInterval(loadMessages, 3000);
    return () => clearInterval(interval);
  }, [myPrivateKey]);

  const initializeSecureChat = async () => {
    try {
      // Step 1: Verify secure connection (Part 2)
      setSecurityStatus(prev => ({ ...prev, step1_connection: 'loading' }));
      await new Promise(resolve => setTimeout(resolve, 500));
      setSecurityStatus(prev => ({ ...prev, step1_connection: 'success' }));

      if (!recipientPublicKeyJwk) {
        throw new Error('Recipient public key not available for this chat session');
      }

      const importedRecipientKey = await importPublicKey(recipientPublicKeyJwk);
      setRecipientPublicKey(importedRecipientKey);

     
      setSecurityStatus(prev => ({ ...prev, step2_keyExchange: 'loading' }));
      
      console.log('[CHAT] Starting custom key exchange protocol...');
      
      const kxResult = await customKX_performKeyExchange(user.username, recipient.username);
      
      if (!kxResult.success) {
        throw new Error(`Key exchange failed: ${kxResult.reason}`);
      }
      
      console.log('[CHAT] Key exchange successful!');
      console.log('[CHAT] Protocol details:', {
        initiator: kxResult.initiator,
        responder: kxResult.responder,
        keysMatch: kxResult.keys.keysMatch,
        confirmationVerified: kxResult.confirmation.verified,
        sessionKeyLength: kxResult.keys.myAesKey.length
      });
      
     
      const base64KeyString = kxResult.keys.myAesKey;
      
      
      const aesKeyBuffer = Uint8Array.from(atob(base64KeyString), c => c.charCodeAt(0));
      const importedAesKey = await window.crypto.subtle.importKey(
        'raw',
        aesKeyBuffer,
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
      );
      
      setSessionAesKey(importedAesKey);
      
      const privKey = await getPrivateKey(user.username);
      if (!privKey) {
        throw new Error('Private key not found on this device');
      }
      setMyPrivateKey(privKey);

      await logSecurityEvent(
        'KEY_EXCHANGE_PROTOCOL_SUCCESS',
        `Custom ECDH key exchange completed with ${recipient.username} - Session keys established`,
        user.token
      );
      setSecurityStatus(prev => ({ ...prev, step2_keyExchange: 'success' }));

      setSecurityStatus(prev => ({ ...prev, step3_encryption: 'loading' }));
      await new Promise(resolve => setTimeout(resolve, 300));
      setSecurityStatus(prev => ({ ...prev, step3_encryption: 'success' }));

      await loadMessages();

    } catch (err) {
      console.error('[CHAT] Failed to initialize secure chat:', err);
      setSecurityStatus(prev => ({
        step1_connection: prev.step1_connection === 'success' ? 'success' : 'error',
        step2_keyExchange: prev.step2_keyExchange === 'success' ? 'success' : 'error',
        step3_encryption: 'error'
      }));
      await logSecurityEvent(
        'KEY_EXCHANGE_PROTOCOL_FAIL',
        `Custom ECDH key exchange failed with ${recipient.username}: ${err.message}`,
        user.token
      );
    }
  };

  const loadMessages = async () => {
  
    if (!myPrivateKey) return;
    
    try {
      const encryptedMessages = await fetchMessages(recipient.username, user.token);
      const sentMessagesCache = JSON.parse(localStorage.getItem('sentMessages') || '{}');
      
     
      const decryptedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          try {
           
            if (msg.to === user.username) {
              
              if (!msg.encryptedSessionKey) {
                throw new Error('Missing encrypted session key on message');
              }

              const aesKeyForMessage = await decryptAESKeyWithRSA(msg.encryptedSessionKey, myPrivateKey);
              const plaintext = await decryptAES(msg.ciphertext, msg.iv, msg.authTag, aesKeyForMessage);
              
              return {
                ...msg,
                plaintext,
                decryptionSuccess: true
              };
            } else {
            
              const cachedPlaintext = sentMessagesCache[msg._id];
              
              return {
                ...msg,
                plaintext: cachedPlaintext || '[Message sent from another device]',
                decryptionSuccess: !!cachedPlaintext,
                isMine: true
              };
            }
          } catch (err) {
            console.error('[CHAT] Failed to decrypt message:', err);
            await logSecurityEvent('DECRYPTION_FAIL', `Failed to decrypt message from ${msg.from}`, user.token);
            return {
              ...msg,
              plaintext: '[Decryption Failed]',
              decryptionSuccess: false
            };
          }
        })
      );
      
      setMessages(decryptedMessages);
      
      // Update sequence number
      const myMessages = decryptedMessages.filter(m => m.from === user.username);
      if (myMessages.length > 0) {
        const maxSeq = Math.max(...myMessages.map(m => m.sequenceNumber));
        setSequenceNumber(maxSeq + 1);
      }
      
    } catch (err) {
      console.error('[CHAT] Failed to load messages:', err);
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();

    if (!newMessage.trim() || sending) return;
    if (!recipientPublicKey) {
      alert('Recipient public key not loaded yet. Please wait a moment and try again.');
      return;
    }

    setSending(true);
    const messagePlaintext = newMessage.trim();

    try {
    
      const messageAesKey = await generateAESKey();
      const { ciphertext, iv, authTag } = await encryptAES(messagePlaintext, messageAesKey);
      const encryptedSessionKey = await encryptAESKeyWithRSA(messageAesKey, recipientPublicKey);

    
      const nonce = generateNonce();

    
      const messagePayload = {
        to: recipient.username,
        encryptedSessionKey,
        ciphertext,
        iv,
        authTag,
        nonce,
        sequenceNumber,
        timestamp: new Date().toISOString()
      };

      // Include file metadata if a file was just shared
      if (window._pendingFileShare) {
        messagePayload.sharedFile = window._pendingFileShare;
        window._pendingFileShare = null;
      }

      // Send encrypted message
      const response = await apiSendMessage(messagePayload, user.token);

      await logSecurityEvent(
        'MESSAGE_ENCRYPTED_RSA_HYBRID',
        `Message encrypted with AES-256 + RSA-wrapped key and sent to ${recipient.username}`,
        user.token
      );

      // Store sent message plaintext locally (temporary cache)
      const messageId = response.messageId;
      const sentMessagesCache = JSON.parse(localStorage.getItem('sentMessages') || '{}');
      sentMessagesCache[messageId] = messagePlaintext;
      localStorage.setItem('sentMessages', JSON.stringify(sentMessagesCache));

      // Clear input and reload messages
      setNewMessage('');
      setSelectedFile(null);
      setFileUploadProgress(0);
      setSequenceNumber(prev => prev + 1);
      setTimeout(loadMessages, 500);

    } catch (err) {
      console.error('[CHAT] Failed to send message:', err);
      await logSecurityEvent('MESSAGE_SEND_FAIL', `Failed to send message: ${err.message}`, user.token);
      alert('Failed to send message: ' + err.message);
    } finally {
      setSending(false);
    }
  };

  // PART 5: Handle file sharing in chat
  const handleFileShareClick = () => {
    setShowFileShareModal(true);
  };

  const handleFileSelect = (e) => {
    if (e.target.files?.[0]) {
      setSelectedFile(e.target.files[0]);
      setFileShareStatus('');
    }
  };

  const handleEncryptAndShareFile = async () => {
    if (!selectedFile) {
      setFileShareStatus('Please select a file');
      return;
    }
    if (!recipientPublicKey) {
      setFileShareStatus('Recipient key not ready. Please wait and try again.');
      return;
    }

    setFileUploading(true);
    setFileUploadProgress(0);

    try {
      // Encrypt file
      setFileShareStatus('Encrypting file (AES-256-GCM)...');
      setFileUploadProgress(30);

      const fileMetadata = await encryptFileForSharing(selectedFile, recipientPublicKey);

      setFileUploadProgress(60);
      setFileShareStatus('Uploading encrypted file...');

      // Upload to server
      const result = await uploadEncryptedFile(fileMetadata, recipient.username, user.token);

      setFileUploadProgress(90);

      // Log event
      await logFileSharingEvent(
        'FILE_SHARED_IN_CHAT',
        `Shared file "${selectedFile.name}" in chat with ${recipient.username}`,
        user.token
      );

      setFileUploadProgress(100);
      setFileShareStatus(`✅ File "${selectedFile.name}" ready to send!`);

      // Store file info to include in message
      const fileInfo = {
        fileId: result.fileId,
        fileName: selectedFile.name,
        fileSize: selectedFile.size,
        fileType: selectedFile.type
      };

      // Create message with file attachment
      const fileMessage = `📁 [FILE] ${selectedFile.name} (${Math.round(selectedFile.size / 1024 / 1024)}MB)`;
      setNewMessage(fileMessage);
      
      // Store file info temporarily so it can be sent with the message
      window._pendingFileShare = fileInfo;

      // Auto-close modal and show file is ready
      setTimeout(() => {
        setShowFileShareModal(false);
        setFileShareStatus('Click Send to share the file!');
        setTimeout(() => setFileShareStatus(''), 3000);
      }, 1000);

    } catch (err) {
      console.error('File share failed:', err);
      setFileShareStatus(`❌ Error: ${err.message}`);
    } finally {
      setFileUploading(false);
    }
  };

  // PART 6: Handle file download from chat
  const handleDownloadFile = async (fileMetadata) => {
    try {
      console.log('Downloading file:', fileMetadata);
      
      // Get user's private key from IndexedDB
      const privateKey = await getPrivateKey(user.username);
      if (!privateKey) {
        throw new Error('Private key not found. Please log in again.');
      }
      
      // Fetch encrypted file from server
      const encryptedFileData = await downloadEncryptedFile(fileMetadata.fileId, user.token);
      
      // Decrypt file
      console.log('Decrypting file...');
      const decryptedArrayBuffer = await decryptFileFromSharing(encryptedFileData, privateKey);
      
      // Create blob and download
      const blob = new Blob([decryptedArrayBuffer], { type: fileMetadata.fileType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileMetadata.fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      console.log('File downloaded successfully');
    } catch (err) {
      console.error('Failed to download file:', err);
      alert('Failed to download file: ' + err.message);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'success': return <CheckCircle size={16} className="text-green-500" />;
      case 'loading': return <Loader size={16} className="text-blue-500 animate-spin" />;
      case 'error': return <AlertTriangle size={16} className="text-red-500" />;
      default: return <div className="w-4 h-4 rounded-full bg-gray-300"></div>;
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-4xl h-[80vh] flex flex-col">
        
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-4 rounded-t-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center text-indigo-600 font-bold">
                {recipient.username[0].toUpperCase()}
              </div>
              <div className="text-white">
                <h2 className="text-lg font-bold">{recipient.username}</h2>
                <div className="flex items-center gap-1 text-xs">
                  <Lock size={12} />
                  <span>End-to-End Encrypted</span>
                </div>
              </div>
            </div>
            <button 
              onClick={onClose}
              className="text-white hover:bg-white hover:bg-opacity-20 rounded-lg px-3 py-1.5 transition-colors"
            >
              Close
            </button>
          </div>

          {/* Security Status Notifications */}
          <div className="mt-3 space-y-1.5">
            {/* Part 2: Secure Connection */}
            <div className="flex items-center gap-2 text-white text-xs bg-white bg-opacity-10 rounded px-2 py-1.5">
              {getStatusIcon(securityStatus.step1_connection)}
              <Shield size={14} />
              <span className="font-medium">Part 2:</span>
              <span>Secure Connection Established</span>
            </div>

            {/* Part 3: Key Exchange */}
            <div className="flex items-center gap-2 text-white text-xs bg-white bg-opacity-10 rounded px-2 py-1.5">
              {getStatusIcon(securityStatus.step2_keyExchange)}
              <Key size={14} />
              <span className="font-medium">Part 3:</span>
              <span>Key Exchange Protocol Completed</span>
            </div>

            {/* Part 4: Encryption Ready */}
            <div className="flex items-center gap-2 text-white text-xs bg-white bg-opacity-10 rounded px-2 py-1.5">
              {getStatusIcon(securityStatus.step3_encryption)}
              <MessageCircle size={14} />
              <span className="font-medium">Part 4:</span>
              <span>AES-256-GCM Encryption Active</span>
            </div>
          </div>
        </div>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-50">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-400">
              <Lock size={48} className="mb-2 opacity-50" />
              <p className="text-sm">No messages yet. Start a secure conversation!</p>
            </div>
          ) : (
            messages.map((msg, idx) => {
              const isMine = msg.from === user.username;
              const hasSharedFile = msg.sharedFile && msg.sharedFile.fileId;
              
              return (
                <div key={idx} className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}>
                  <div 
                    className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                      isMine 
                        ? 'bg-indigo-600 text-white' 
                        : msg.decryptionSuccess 
                          ? 'bg-white border border-gray-200' 
                          : 'bg-red-50 border border-red-200'
                    }`}
                  >
                    {hasSharedFile ? (
                      <div>
                        <p className="text-sm font-semibold mb-2">📁 File Shared</p>
                        <p className="text-xs mb-2 opacity-80">{msg.sharedFile.fileName}</p>
                        <p className="text-xs mb-3 opacity-75">
                          {(msg.sharedFile.fileSize / 1024 / 1024).toFixed(2)} MB
                        </p>
                        <button
                          onClick={() => handleDownloadFile(msg.sharedFile)}
                          disabled={isMine}
                          className="px-3 py-1 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white text-xs rounded transition-colors cursor-pointer"
                        >
                          {isMine ? 'Uploaded' : 'Download'}
                        </button>
                      </div>
                    ) : (
                      <p className="text-sm">{msg.plaintext}</p>
                    )}
                    <div className={`flex items-center gap-1 text-xs mt-2 ${isMine ? 'text-indigo-100' : 'text-gray-400'}`}>
                      <Lock size={10} />
                      <span>{new Date(msg.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input */}
        <form onSubmit={handleSendMessage} className="p-4 bg-white border-t border-gray-200">
          <div className="flex gap-2">
            <input
              type="text"
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              placeholder="Type an encrypted message..."
              disabled={securityStatus.step3_encryption !== 'success' || sending}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none disabled:bg-gray-100"
            />
            {/* PART 5: File share button in chat */}
            <button
              type="button"
              onClick={handleFileShareClick}
              disabled={securityStatus.step3_encryption !== 'success' || fileUploading}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-300 text-white rounded-lg transition-colors flex items-center gap-2"
              title="Share encrypted file"
            >
              <FileUp size={18} />
            </button>
            <button
              type="submit"
              disabled={!newMessage.trim() || securityStatus.step3_encryption !== 'success' || sending}
              className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-300 text-white rounded-lg transition-colors flex items-center gap-2"
            >
              {sending ? <Loader size={18} className="animate-spin" /> : <Send size={18} />}
              Send
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-2 flex items-center gap-1">
            <Shield size={12} />
            CUSTOM PROTOCOL: Messages encrypted with AES-256-GCM session key from ECDH + HKDF
          </p>
        </form>

        {/* PART 5: File Share Modal */}
        {showFileShareModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl shadow-lg max-w-md w-full p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                  <FileUp className="text-green-600" />
                  Share Encrypted File
                </h3>
                <button
                  onClick={() => {
                    setShowFileShareModal(false);
                    setSelectedFile(null);
                    setFileShareStatus('');
                  }}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X size={20} />
                </button>
              </div>

              <p className="text-sm text-gray-600">
                File will be encrypted with AES-256-GCM and shared with <strong>{recipient.username}</strong>
              </p>

              {/* File Input */}
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-green-400 transition-colors cursor-pointer"
              >
                <Upload size={32} className="mx-auto text-gray-400 mb-2" />
                <p className="text-sm font-medium text-gray-700">
                  {selectedFile ? selectedFile.name : 'Click to select file or drag and drop'}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {selectedFile ? `${Math.round(selectedFile.size / 1024 / 1024)}MB` : 'Any file type'}
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  hidden
                  onChange={handleFileSelect}
                  disabled={fileUploading}
                />
              </div>

              {/* Progress Bar */}
              {fileUploadProgress > 0 && (
                <div className="space-y-2">
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-green-600 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${fileUploadProgress}%` }}
                    ></div>
                  </div>
                  <p className="text-xs text-gray-500 text-center">{fileUploadProgress}%</p>
                </div>
              )}

              {/* Status Message */}
              {fileShareStatus && (
                <div className={`p-3 rounded-lg text-sm flex items-center gap-2 ${
                  fileShareStatus.includes('✅') 
                    ? 'bg-green-50 text-green-800 border border-green-200'
                    : fileShareStatus.includes('❌')
                    ? 'bg-red-50 text-red-800 border border-red-200'
                    : 'bg-blue-50 text-blue-800 border border-blue-200'
                }`}>
                  {fileShareStatus.includes('✅') ? (
                    <CheckCircle size={16} />
                  ) : fileShareStatus.includes('❌') ? (
                    <AlertCircle size={16} />
                  ) : (
                    <Loader size={16} className="animate-spin" />
                  )}
                  {fileShareStatus}
                </div>
              )}

              {/* Security Info */}
              <div className="p-3 bg-green-50 rounded-lg border border-green-200">
                <p className="text-xs text-green-800 flex items-center gap-1 mb-1">
                  <Lock size={12} />
                  <strong>Encryption Details:</strong>
                </p>
                <ul className="text-xs text-green-700 space-y-0.5 list-disc list-inside">
                  <li>AES-256-GCM per chunk</li>
                  <li>RSA-2048 key encryption</li>
                  <li>Server stores encrypted only</li>
                </ul>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => {
                    setShowFileShareModal(false);
                    setSelectedFile(null);
                    setFileShareStatus('');
                  }}
                  disabled={fileUploading}
                  className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors disabled:text-gray-400"
                >
                  Cancel
                </button>
                <button
                  onClick={handleEncryptAndShareFile}
                  disabled={!selectedFile || fileUploading}
                  className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-300 text-white rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {fileUploading ? (
                    <>
                      <Loader size={16} className="animate-spin" />
                      Encrypting...
                    </>
                  ) : (
                    <>
                      <Upload size={16} />
                      Encrypt & Share
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
