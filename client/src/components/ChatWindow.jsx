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
  // REAL KEY EXCHANGE PROTOCOL FUNCTIONS
  customKX_initiateKeyExchange,
  customKX_finalizeKeyExchange_initiator,
  customKX_respondToKeyExchange,
  customKX_finalizeKeyExchange_responder,
  customKX_importPublicKeyJwk
} from '../utils/crypto';

import { 
  sendMessage as apiSendMessage,
  fetchMessages,
  logSecurityEvent,
  uploadEncryptedFile,
  logFileSharingEvent,
  downloadEncryptedFile,
  sendKXHello,
  fetchKXResponse,
  sendKXConfirm,
  fetchPendingKeyExchanges,
  sendKXResponse as apiSendKXResponse,
  fetchKXConfirm,
  fetchUserSigningPublicKey
} from '../utils/api';

import { getPrivateKey, getSigningPrivateKey } from '../utils/indexedDB';

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
    if (!sessionAesKey) return;
    const interval = setInterval(loadMessages, 3000);
    return () => clearInterval(interval);
  }, [sessionAesKey]);

  // Background polling for incoming key exchange requests (responder side)
  useEffect(() => {
    if (!user) return;
    
    const pollForIncomingKeyExchanges = async () => {
      try {
        const mySigningPrivateKey = await getSigningPrivateKey(user.username);
        if (!mySigningPrivateKey) {
          console.log('[KX] No signing private key available for responder');
          return;
        }
        
        // Fetch pending key exchanges
        const pending = await fetchPendingKeyExchanges(user.token);
        
        if (pending.length > 0) {
          console.log(`[KX] Found ${pending.length} pending key exchange(s)`);
        }
        
        for (const pendingKX of pending) {
          try {
            console.log(`[KX] Processing key exchange from ${pendingKX.initiator}, sessionId: ${pendingKX.sessionId}`);
            
            // Fetch initiator's signing public key
            const initiatorSigningKeyData = await fetchUserSigningPublicKey(
              pendingKX.initiator,
              user.token
            );
            
            if (!initiatorSigningKeyData || !initiatorSigningKeyData.signingPublicKey) {
              console.error('[KX] Failed to fetch initiator signing public key');
              continue;
            }
            
            const initiatorSigningPublicKey = await customKX_importPublicKeyJwk(
              initiatorSigningKeyData.signingPublicKey,
              'ecdsa'
            );
            
            // Respond to key exchange (use sessionId from pending exchange)
            const responseResult = await customKX_respondToKeyExchange(
              user.username,
              pendingKX.initiator,
              pendingKX.sessionId, // Use the sessionId from the pending exchange
              pendingKX.kxHelloMsg,
              pendingKX.helloSignature,
              mySigningPrivateKey,
              initiatorSigningPublicKey
            );
            
            if (!responseResult.success) {
              console.error('[KX] Response failed:', responseResult.reason);
              continue;
            }
            
            console.log(`[KX] Sending KX_RESPONSE for session ${pendingKX.sessionId}`);
            
            // Send response to server
            await apiSendKXResponse(
              pendingKX.sessionId,
              responseResult.kxResponseMsg,
              responseResult.responseSignature,
              user.token
            );
            
            console.log(`[KX] KX_RESPONSE sent, waiting for confirmation...`);
            
            // Poll for confirmation
            let confirmReceived = false;
            let confirmAttempts = 0;
            while (!confirmReceived && confirmAttempts < 10) {
              await new Promise(resolve => setTimeout(resolve, 1000));
              
              const confirmData = await fetchKXConfirm(pendingKX.sessionId, user.token);
              
              if (confirmData.status === 'confirmed') {
                console.log(`[KX] Confirmation received for session ${pendingKX.sessionId}`);
                
                // Finalize
                const finalizeResult = await customKX_finalizeKeyExchange_responder(
                  pendingKX.sessionId,
                  confirmData.confirmTag,
                  confirmData.salt
                );
                
                if (finalizeResult.success) {
                  // Store session keys
                  const { storeEstablishedSessionKeys } = await import('../utils/keyExchangeState');
                  storeEstablishedSessionKeys(
                    user.username,
                    pendingKX.initiator,
                    finalizeResult.aesKey,
                    finalizeResult.hmacKey
                  );
                  
                  console.log('[KX] ✓ Key exchange completed as responder');
                  
                  // If this is for the current chat, update session key
                  if (recipient && recipient.username === pendingKX.initiator) {
                    setSessionAesKey(finalizeResult.aesKey);
                    setSecurityStatus(prev => ({ ...prev, step2_keyExchange: 'success', step3_encryption: 'success' }));
                    console.log('[KX] Session key updated for active chat');
                  }
                } else {
                  console.error('[KX] Finalization failed:', finalizeResult.reason);
                }
                
                confirmReceived = true;
              }
              
              confirmAttempts++;
            }
            
            if (!confirmReceived) {
              console.warn(`[KX] Confirmation timeout for session ${pendingKX.sessionId}`);
            }
            
          } catch (err) {
            console.error('[KX] Error processing pending key exchange:', err);
          }
        }
        
      } catch (err) {
        console.error('[KX] Polling error:', err);
      }
    };
    
    // Poll every 3 seconds (more frequent for better responsiveness)
    const interval = setInterval(pollForIncomingKeyExchanges, 3000);
    
    // Run immediately on mount
    pollForIncomingKeyExchanges();
    
    return () => clearInterval(interval);
  }, [user, recipient]);

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

      // Step 2: REAL KEY EXCHANGE PROTOCOL
      setSecurityStatus(prev => ({ ...prev, step2_keyExchange: 'loading' }));
      
      // Get my signing private key
      const mySigningPrivateKey = await getSigningPrivateKey(user.username);
      if (!mySigningPrivateKey) {
        throw new Error('Signing private key not found. Please re-register.');
      }
      
      // Fetch recipient's signing public key
      let recipientSigningKeyData;
      try {
        recipientSigningKeyData = await fetchUserSigningPublicKey(recipient.username, user.token);
        if (!recipientSigningKeyData || !recipientSigningKeyData.signingPublicKey) {
          throw new Error('Recipient does not have a signing public key. They may need to re-register.');
        }
      } catch (err) {
        console.error('[CHAT] Failed to fetch recipient signing key:', err);
        throw new Error(`Cannot start key exchange: ${err.message || 'Recipient signing key not found'}`);
      }
      
      const recipientSigningPublicKey = await customKX_importPublicKeyJwk(
        recipientSigningKeyData.signingPublicKey,
        'ecdsa'
      );
      
      // INITIATOR FLOW: Send KX_HELLO
      const initResult = await customKX_initiateKeyExchange(
        user.username,
        recipient.username,
        mySigningPrivateKey
      );
      
      if (!initResult.success) {
        throw new Error(initResult.reason);
      }
      
      // Use the sessionId returned from initiateKeyExchange (not a new one!)
      const sessionId = initResult.sessionId;
      console.log(`[KX] Initiator: Starting key exchange with sessionId: ${sessionId}`);
      
      // Send KX_HELLO to server
      await sendKXHello(
        sessionId,
        initResult.kxHelloMsg,
        initResult.helloSignature,
        recipient.username,
        user.token
      );
      
      console.log(`[KX] Initiator: KX_HELLO sent, polling for KX_RESPONSE...`);
      
      // Poll for KX_RESPONSE (with timeout)
      let responseReceived = false;
      let pollAttempts = 0;
      const maxPollAttempts = 30; // 30 attempts * 1 second = 30 seconds timeout
      
      while (!responseReceived && pollAttempts < maxPollAttempts) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
        
        try {
          const responseData = await fetchKXResponse(sessionId, user.token);
          
          if (responseData.status === 'ready') {
            console.log(`[KX] Initiator: KX_RESPONSE received for session ${sessionId}`);
            
            // Finalize key exchange
            const finalizeResult = await customKX_finalizeKeyExchange_initiator(
              sessionId,
              responseData.kxResponseMsg,
              responseData.responseSignature
            );
            
            if (!finalizeResult.success) {
              throw new Error(finalizeResult.reason);
            }
            
            console.log(`[KX] Initiator: Sending KX_CONFIRM for session ${sessionId}`);
            
            // Send confirmation
            await sendKXConfirm(
              sessionId,
              finalizeResult.confirmTag,
              finalizeResult.salt,
              user.token
            );
            
            // Store session AES key
            setSessionAesKey(finalizeResult.aesKey);
            responseReceived = true;
            console.log(`[KX] Initiator: ✓ Key exchange completed`);
          } else if (responseData.status === 'pending') {
            console.log(`[KX] Initiator: Still waiting for response (attempt ${pollAttempts + 1}/${maxPollAttempts})`);
          }
        } catch (err) {
          console.error(`[KX] Initiator: Error polling for response:`, err);
          // Continue polling despite errors
        }
        
        pollAttempts++;
      }
      
      if (!responseReceived) {
        throw new Error(`Key exchange timeout - responder did not respond within ${maxPollAttempts} seconds`);
      }
      
      // Also load RSA private key for file sharing
      const privKey = await getPrivateKey(user.username);
      if (!privKey) {
        throw new Error('Private key not found on this device');
      }
      setMyPrivateKey(privKey);

      await logSecurityEvent(
        'KEY_EXCHANGE_PROTOCOL_SUCCESS',
        `Real ECDH key exchange completed with ${recipient.username}`,
        user.token
      );
      
      setSecurityStatus(prev => ({ ...prev, step2_keyExchange: 'success' }));

      // Step 3: Encryption ready (Part 4)
      setSecurityStatus(prev => ({ ...prev, step3_encryption: 'loading' }));
      await new Promise(resolve => setTimeout(resolve, 300));
      setSecurityStatus(prev => ({ ...prev, step3_encryption: 'success' }));

      // Load existing messages
      await loadMessages();

    } catch (err) {
      console.error('[CHAT] Failed to initialize secure chat:', err);
      setSecurityStatus(prev => ({
        step1_connection: prev.step1_connection === 'success' ? 'success' : 'error',
        step2_keyExchange: 'error',
        step3_encryption: 'error'
      }));
      await logSecurityEvent(
        'KEY_EXCHANGE_PROTOCOL_FAIL',
        `Key exchange failed with ${recipient.username}: ${err.message}`,
        user.token
      );
    }
  };

  const loadMessages = async () => {
    if (!sessionAesKey) return; // Wait for session key
    
    try {
      const encryptedMessages = await fetchMessages(recipient.username, user.token);
      const sentMessagesCache = JSON.parse(localStorage.getItem('sentMessages') || '{}');
      
      const decryptedMessages = await Promise.all(
        encryptedMessages.map(async (msg) => {
          try {
            if (msg.to === user.username) {
              // Message sent TO me
              // Check if it uses session key or old RSA-wrapped key
              if (msg.usesSessionKey && sessionAesKey) {
                // Use session key
                const plaintext = await decryptAES(msg.ciphertext, msg.iv, msg.authTag, sessionAesKey);
                
                return {
                  ...msg,
                  plaintext,
                  decryptionSuccess: true
                };
              } else if (msg.encryptedSessionKey && myPrivateKey) {
                // Fallback to old RSA-wrapped key (backward compatibility)
                const aesKeyForMessage = await decryptAESKeyWithRSA(msg.encryptedSessionKey, myPrivateKey);
                const plaintext = await decryptAES(msg.ciphertext, msg.iv, msg.authTag, aesKeyForMessage);
                
                return {
                  ...msg,
                  plaintext,
                  decryptionSuccess: true
                };
              } else {
                throw new Error('No decryption method available');
              }
            } else {
              // Message sent BY me - retrieve from local cache
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
    // Ensure we have a message and the recipient's RSA public key
    if (!newMessage.trim() || sending) return;
    if (!recipientPublicKey) {
      alert('Recipient public key not loaded yet. Please wait a moment and try again.');
      return;
    }

    setSending(true);
    const messagePlaintext = newMessage.trim();

    try {
      // Generate fresh AES-256 key per message (hybrid encryption with RSA key wrap)
      const messageAesKey = await generateAESKey();
      const { ciphertext, iv, authTag } = await encryptAES(messagePlaintext, messageAesKey);
      const encryptedSessionKey = await encryptAESKeyWithRSA(messageAesKey, recipientPublicKey);

      // Generate nonce for replay protection (still needed at message level)
      const nonce = generateNonce();

      // Prepare message payload
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
