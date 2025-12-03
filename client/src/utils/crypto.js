/**
 * Part 1: Cryptography Functions
 * RSA-OAEP key generation and management using Web Crypto API
 */

export const generateKeyPair = async () => {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    return keyPair;
  } catch (err) {
    console.error("Key generation failed", err);
    throw new Error("Crypto API Error");
  }
};

export const exportKey = async (key) => {
  return await window.crypto.subtle.exportKey("jwk", key);
};

export const importPublicKey = async (jwk) => {
  try {
    return await window.crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  } catch (err) {
    console.error("Public key import failed", err);
    throw new Error("Failed to import public key");
  }
};

export const generateAESKey = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
};

export const encryptAES = async (plaintext, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128 // 128-bit authentication tag
    },
    key,
    data
  );

  const ciphertextArray = new Uint8Array(ciphertext);
  const actualCiphertext = ciphertextArray.slice(0, -16);
  const authTag = ciphertextArray.slice(-16);

  return {
    ciphertext: arrayBufferToBase64(actualCiphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag)
  };
};

export const decryptAES = async (ciphertextB64, ivB64, authTagB64, key) => {
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);
  const authTag = base64ToArrayBuffer(authTagB64);

  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(new Uint8Array(ciphertext), 0);
  combined.set(new Uint8Array(authTag), ciphertext.byteLength);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        tagLength: 128
      },
      key,
      combined
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (err) {
    console.error("Decryption failed", err);
    throw new Error("Failed to decrypt message - invalid key or corrupted data");
  }
};

export const encryptAESKeyWithRSA = async (aesKey, publicKey) => {
  const rawAESKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    rawAESKey
  );
  return arrayBufferToBase64(encrypted);
};

export const decryptAESKeyWithRSA = async (encryptedKeyB64, privateKey) => {
  const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);
  
  const decryptedKey = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    encryptedKey
  );

  return await window.crypto.subtle.importKey(
    "raw",
    decryptedKey,
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
};

export const generateNonce = () => {
  const nonce = window.crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(nonce);
};

export const arrayBufferToBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

export const base64ToArrayBuffer = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

export const chunkFile = (file, chunkSize = 5 * 1024 * 1024) => {
  const chunks = [];
  const fileSize = file.size;
  let offset = 0;

  while (offset < fileSize) {
    const end = Math.min(offset + chunkSize, fileSize);
    chunks.push(file.slice(offset, end));
    offset = end;
  }

  return chunks;
};

export const encryptFileChunk = async (chunk, aesKey) => {
  const arrayBuffer = await chunk.arrayBuffer();
  
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
   
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128
    },
    aesKey,
    arrayBuffer
  );

  const encryptedArray = new Uint8Array(encryptedData);
  const actualCiphertext = encryptedArray.slice(0, -16);
  const authTag = encryptedArray.slice(-16);

  return {
    ciphertext: arrayBufferToBase64(actualCiphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
    chunkSize: chunk.size
  };
};

export const decryptFileChunk = async (ciphertextB64, ivB64, authTagB64, aesKey) => {
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);
  const authTag = base64ToArrayBuffer(authTagB64);

  const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  combined.set(new Uint8Array(ciphertext), 0);
  combined.set(new Uint8Array(authTag), ciphertext.byteLength);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        tagLength: 128
      },
      aesKey,
      combined
    );

    return decrypted;
  } catch (err) {
    console.error("File chunk decryption failed:", err);
    throw new Error("Failed to decrypt file chunk - invalid key or corrupted data");
  }
};

export const encryptFileForSharing = async (file, recipientPublicKey, chunkSize = 5 * 1024 * 1024) => {
  try {
    const aesKey = await generateAESKey();

    const chunks = chunkFile(file, chunkSize);
    
    const encryptedChunks = [];
    for (let i = 0; i < chunks.length; i++) {
      const encryptedChunk = await encryptFileChunk(chunks[i], aesKey);
      encryptedChunks.push({
        chunkIndex: i,
        ...encryptedChunk
      });
    }

    const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, recipientPublicKey);

    const fileMetadata = {
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      totalChunks: chunks.length,
      chunkSize: chunkSize,
      encryptedAESKey: encryptedAESKey,
      encryptedChunks: encryptedChunks,
      timestamp: new Date().toISOString()
    };

    return fileMetadata;
  } catch (err) {
    console.error("File encryption failed:", err);
    throw new Error("Failed to encrypt file");
  }
};

export const decryptFileFromSharing = async (fileMetadata, myPrivateKey) => {
  try {
    const aesKey = await decryptAESKeyWithRSA(fileMetadata.encryptedAESKey, myPrivateKey);

    const decryptedChunks = [];
    for (const encryptedChunk of fileMetadata.encryptedChunks) {
      const decryptedData = await decryptFileChunk(
        encryptedChunk.ciphertext,
        encryptedChunk.iv,
        encryptedChunk.authTag,
        aesKey
      );
      decryptedChunks.push(new Uint8Array(decryptedData));
    }

    const concatenated = new Uint8Array(
      decryptedChunks.reduce((acc, chunk) => acc + chunk.length, 0)
    );
    
    let offset = 0;
    for (const chunk of decryptedChunks) {
      concatenated.set(chunk, offset);
      offset += chunk.length;
    }
    
    const fileBlob = new Blob([concatenated], { type: fileMetadata.fileType || 'application/octet-stream' });

    return fileBlob;
  } catch (err) {
    console.error("File decryption failed:", err);
    throw new Error("Failed to decrypt file");
  }
};

export const customKX_generateEphemeralKeyPair = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveBits', 'deriveKey']
  );
};

export const customKX_generateLongTermSigningKeyPair = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );
};

export const customKX_exportPublicKeyJwk = async (publicKey) => {
  return await window.crypto.subtle.exportKey('jwk', publicKey);
};

export const customKX_importPublicKeyJwk = async (jwk, keyType = 'ecdh') => {
  const algName = keyType === 'ecdsa' ? 'ECDSA' : 'ECDH';
  const usage = keyType === 'ecdsa' ? ['verify'] : [];
  
  return await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: algName, namedCurve: 'P-256' },
    true,
    usage
  );
};

export const customKX_signData = async (signingPrivateKey, dataToSign) => {
  const signature = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPrivateKey,
    dataToSign
  );
  return arrayBufferToBase64(signature);
};

export const customKX_verifySignature = async (signingPublicKey, dataToVerify, signatureB64) => {
  const sig = base64ToArrayBuffer(signatureB64);
  try {
    return await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingPublicKey,
      sig,
      dataToVerify
    );
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
};

export const customKX_deriveSharedSecret = async (myEphemeralPrivateKey, peerEphemeralPublicKey) => {
  return await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerEphemeralPublicKey },
    myEphemeralPrivateKey,
    256 // 256 bits = 32 bytes
  );
};

export const customKX_hkdfDeriveSessionKeys = async (sharedSecretBits, salt = null) => {
  const actualSalt = salt || window.crypto.getRandomValues(new Uint8Array(16));
  
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    sharedSecretBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  
  const info1 = new TextEncoder().encode('InfoSecProject-KEX-AES-Session-Key-v1');
  const info2 = new TextEncoder().encode('InfoSecProject-KEX-HMAC-Confirm-Key-v1');
  
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: actualSalt,
      info: info1
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  const hmacKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: actualSalt,
      info: info2
    },
    baseKey,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  
  return {
    aesKey,
    hmacKey,
    salt: arrayBufferToBase64(actualSalt)
  };
};

export const customKX_computeKeyConfirmation = async (hmacKey, transcriptBytes) => {
  const confirmationTag = await window.crypto.subtle.sign(
    'HMAC',
    hmacKey,
    transcriptBytes
  );
  return arrayBufferToBase64(confirmationTag);
};

export const customKX_verifyKeyConfirmation = async (hmacKey, transcriptBytes, peerConfirmationB64) => {
  const peerConfirmation = base64ToArrayBuffer(peerConfirmationB64);
  try {
    return await window.crypto.subtle.verify(
      'HMAC',
      hmacKey,
      peerConfirmation,
      transcriptBytes
    );
  } catch (e) {
    console.error('Confirmation verification error:', e);
    return false;
  }
};

export const customKX_buildTranscript = (message1, message2 = null) => {
  const transcript = JSON.stringify({ message1, message2 });
  return new TextEncoder().encode(transcript);
};

export const customKX_performKeyExchange = async (myUsername, peerUsername) => {
  try {
    console.log(`[CUSTOM KX] Initiating key exchange: ${myUsername} ↔ ${peerUsername}`);
    
    console.log('[CUSTOM KX] Step 1: Generating my ephemeral and long-term keys...');
    const myEphemeralKeypair = await customKX_generateEphemeralKeyPair();
    const mySigningKeypair = await customKX_generateLongTermSigningKeyPair();
    
    const myEphemeralPubJwk = await customKX_exportPublicKeyJwk(myEphemeralKeypair.publicKey);
    const mySigningPubJwk = await customKX_exportPublicKeyJwk(mySigningKeypair.publicKey);
    
    const myNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
    
    console.log('[CUSTOM KX] Step 2: Creating KX_HELLO message...');
    const kxHelloMsg = {
      id: myUsername,
      ephPub: myEphemeralPubJwk,
      longTermPub: mySigningPubJwk,
      nonce: myNonce
    };
    
    const helloTranscript = customKX_buildTranscript(kxHelloMsg);
    const helloSignature = await customKX_signData(mySigningKeypair.privateKey, helloTranscript);
    
    console.log(`[CUSTOM KX] ✓ Created KX_HELLO with signature from ${myUsername}`);
    

    console.log('[CUSTOM KX] Step 3: Simulating peer KX_RESPONSE...');
    const peerEphemeralKeypair = await customKX_generateEphemeralKeyPair();
    const peerSigningKeypair = await customKX_generateLongTermSigningKeyPair();
    const peerEphemeralPubJwk = await customKX_exportPublicKeyJwk(peerEphemeralKeypair.publicKey);
    const peerSigningPubJwk = await customKX_exportPublicKeyJwk(peerSigningKeypair.publicKey);
    const peerNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
    
    const kxResponseMsg = {
      id: peerUsername,
      ephPub: peerEphemeralPubJwk,
      longTermPub: peerSigningPubJwk,
      nonce: peerNonce
    };
    
    const responseTranscript = customKX_buildTranscript(kxResponseMsg);
    const responseSignature = await customKX_signData(peerSigningKeypair.privateKey, responseTranscript);
    
    console.log(`[CUSTOM KX] ✓ Received simulated KX_RESPONSE from ${peerUsername}`);
    
    console.log('[CUSTOM KX] Step 4: Verifying peer signature...');
    const peerSigningPubKey = await customKX_importPublicKeyJwk(peerSigningPubJwk, 'ecdsa');
    const responseSignatureValid = await customKX_verifySignature(
      peerSigningPubKey,
      responseTranscript,
      responseSignature
    );
    
    if (!responseSignatureValid) {
      console.error('[CUSTOM KX] ✗ FAILED: Peer signature is invalid (possible MITM!)');
      return { success: false, reason: 'Peer signature verification failed' };
    }
    console.log('[CUSTOM KX] ✓ Peer signature valid');
    
    console.log('[CUSTOM KX] Step 5: Deriving shared secret via ECDH...');
    const peerEphemeralPubKey = await customKX_importPublicKeyJwk(peerEphemeralPubJwk, 'ecdh');
    const mySharedSecret = await customKX_deriveSharedSecret(
      myEphemeralKeypair.privateKey,
      peerEphemeralPubKey
    );
    
    const myEphemeralPubKey = await customKX_importPublicKeyJwk(myEphemeralPubJwk, 'ecdh');
    const peerSharedSecret = await customKX_deriveSharedSecret(
      peerEphemeralKeypair.privateKey,
      myEphemeralPubKey
    );
    
    const mySecretBuf = new Uint8Array(mySharedSecret);
    const peerSecretBuf = new Uint8Array(peerSharedSecret);
    const secretsMatch = mySecretBuf.length === peerSecretBuf.length &&
      mySecretBuf.every((v, i) => v === peerSecretBuf[i]);
    
    if (!secretsMatch) {
      console.error('[CUSTOM KX] ✗ FAILED: Shared secrets do not match');
      return { success: false, reason: 'Shared secrets mismatch' };
    }
    console.log('[CUSTOM KX] ✓ Shared secrets match');
    
    console.log('[CUSTOM KX] Step 6: Deriving session keys via HKDF-SHA256...');
    const mySessionKeys = await customKX_hkdfDeriveSessionKeys(mySharedSecret);
    const peerSessionKeys = await customKX_hkdfDeriveSessionKeys(peerSharedSecret, base64ToArrayBuffer(mySessionKeys.salt));
    
    console.log('[CUSTOM KX] ✓ Session keys derived');
    
    console.log('[CUSTOM KX] Step 7: Computing key confirmation...');
    const fullTranscript = customKX_buildTranscript(kxHelloMsg, kxResponseMsg);
    const myConfirmation = await customKX_computeKeyConfirmation(mySessionKeys.hmacKey, fullTranscript);
    const peerConfirmation = await customKX_computeKeyConfirmation(peerSessionKeys.hmacKey, fullTranscript);
    
    const myConfirmOk = await customKX_verifyKeyConfirmation(mySessionKeys.hmacKey, fullTranscript, peerConfirmation);
    const peerConfirmOk = await customKX_verifyKeyConfirmation(peerSessionKeys.hmacKey, fullTranscript, myConfirmation);
    
    if (!myConfirmOk || !peerConfirmOk) {
      console.error('[CUSTOM KX] ✗ FAILED: Key confirmation mismatch');
      return { success: false, reason: 'Key confirmation verification failed' };
    }
    console.log('[CUSTOM KX] ✓ Key confirmation verified');
    
    const rawAesKeyMy = await window.crypto.subtle.exportKey('raw', mySessionKeys.aesKey);
    const rawAesKeyPeer = await window.crypto.subtle.exportKey('raw', peerSessionKeys.aesKey);
    
    console.log(`[CUSTOM KX] ✓✓✓ KEY EXCHANGE SUCCESSFUL ✓✓✓`);
    
    return {
      success: true,
      initiator: myUsername,
      responder: peerUsername,
      steps: {
        ephemeralKeysGenerated: true,
        signingKeysGenerated: true,
        helloCreated: true,
        responseReceived: true,
        signatureVerified: responseSignatureValid,
        sharedSecretDerived: secretsMatch,
        sessionKeysDerived: true,
        confirmationVerified: myConfirmOk && peerConfirmOk
      },
      keys: {
        myAesKey: arrayBufferToBase64(rawAesKeyMy),
        peerAesKey: arrayBufferToBase64(rawAesKeyPeer),
        keysMatch: arrayBufferToBase64(rawAesKeyMy) === arrayBufferToBase64(rawAesKeyPeer),
        salt: mySessionKeys.salt
      },
      confirmation: {
        myTag: myConfirmation.substring(0, 32) + '...',
        peerTag: peerConfirmation.substring(0, 32) + '...',
        verified: myConfirmOk && peerConfirmOk
      },
      transcript: {
        helloMsg: kxHelloMsg,
        responseMsg: kxResponseMsg,
        transcriptLength: fullTranscript.length
      }
    };
  } catch (err) {
    console.error('[CUSTOM KX] Exception occurred:', err);
    return {
      success: false,
      reason: `Key exchange failed: ${err.message}`,
      error: err
    };
  }
};

export const customKX_initiateKeyExchange = async (myUsername, peerUsername, mySigningPrivateKey) => {
    try {
        const { generateSessionId } = await import('./keyExchangeState');
        const sessionId = generateSessionId();
        
        const myEphemeralKeypair = await customKX_generateEphemeralKeyPair();
        const myEphemeralPubJwk = await customKX_exportPublicKeyJwk(myEphemeralKeypair.publicKey);
        
        let mySigningPubJwk;
        try {
            const storedPubJwk = localStorage.getItem(`${myUsername}_signing_pub_jwk`);
            if (storedPubJwk) {
                mySigningPubJwk = JSON.parse(storedPubJwk);
            } else {
                const privateJwk = await window.crypto.subtle.exportKey('jwk', mySigningPrivateKey);
                const { d, ...publicJwk } = privateJwk;
                mySigningPubJwk = publicJwk;
                localStorage.setItem(`${myUsername}_signing_pub_jwk`, JSON.stringify(mySigningPubJwk));
            }
        } catch (err) {
            console.error('[CUSTOM KX] Error getting signing public key:', err);
            throw new Error('Failed to get signing public key');
        }
        
        const myNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
        
        const kxHelloMsg = {
            id: myUsername,
            ephPub: myEphemeralPubJwk,
            longTermPub: mySigningPubJwk,
            nonce: myNonce
        };
        
        const helloTranscript = customKX_buildTranscript(kxHelloMsg);
        const helloSignature = await customKX_signData(mySigningPrivateKey, helloTranscript);
        
        const { storeActiveSession } = await import('./keyExchangeState');
        storeActiveSession(sessionId, {
            role: 'initiator',
            myEphemeralPrivateKey: myEphemeralKeypair.privateKey,
            mySigningPrivateKey: mySigningPrivateKey,
            peerUsername: peerUsername,
            kxHelloMsg: kxHelloMsg,
            helloSignature: helloSignature,
            status: 'hello_sent'
        });
        
        return {
            success: true,
            sessionId: sessionId,
            kxHelloMsg: kxHelloMsg,
            helloSignature: helloSignature
        };
        
    } catch (err) {
        console.error('[CUSTOM KX] Initiation failed:', err);
        return {
            success: false,
            reason: `Key exchange initiation failed: ${err.message}`
        };
    }
};

export const customKX_respondToKeyExchange = async (
    myUsername,
    initiatorUsername,
    sessionId,
    kxHelloMsg,
    helloSignature,
    mySigningPrivateKey,
    initiatorSigningPublicKey
) => {
    try {
        const helloTranscript = customKX_buildTranscript(kxHelloMsg);
        const signatureValid = await customKX_verifySignature(
            initiatorSigningPublicKey,
            helloTranscript,
            helloSignature
        );
        
        if (!signatureValid) {
            return {
                success: false,
                reason: 'Invalid signature from initiator - possible MITM attack'
            };
        }
        
        const myEphemeralKeypair = await customKX_generateEphemeralKeyPair();
        const myEphemeralPubJwk = await customKX_exportPublicKeyJwk(myEphemeralKeypair.publicKey);
        
        let mySigningPubJwk;
        try {
            const storedPubJwk = localStorage.getItem(`${myUsername}_signing_pub_jwk`);
            if (storedPubJwk) {
                mySigningPubJwk = JSON.parse(storedPubJwk);
            } else {
                const privateJwk = await window.crypto.subtle.exportKey('jwk', mySigningPrivateKey);
                const { d, ...publicJwk } = privateJwk;
                mySigningPubJwk = publicJwk;
                localStorage.setItem(`${myUsername}_signing_pub_jwk`, JSON.stringify(mySigningPubJwk));
            }
        } catch (err) {
            console.error('[CUSTOM KX] Error getting signing public key:', err);
            throw new Error('Failed to get signing public key');
        }
        
        const myNonce = arrayBufferToBase64(window.crypto.getRandomValues(new Uint8Array(16)));
        
        const kxResponseMsg = {
            id: myUsername,
            ephPub: myEphemeralPubJwk,
            longTermPub: mySigningPubJwk,
            nonce: myNonce
        };
        
        const responseTranscript = customKX_buildTranscript(kxResponseMsg);
        const responseSignature = await customKX_signData(mySigningPrivateKey, responseTranscript);
        
        const { storeActiveSession } = await import('./keyExchangeState');
        storeActiveSession(sessionId, {
            role: 'responder',
            myEphemeralPrivateKey: myEphemeralKeypair.privateKey,
            mySigningPrivateKey: mySigningPrivateKey,
            peerUsername: initiatorUsername,
            kxHelloMsg: kxHelloMsg,
            helloSignature: helloSignature,
            kxResponseMsg: kxResponseMsg,
            responseSignature: responseSignature,
            status: 'response_sent'
        });
        
        return {
            success: true,
            sessionId: sessionId,
            kxResponseMsg: kxResponseMsg,
            responseSignature: responseSignature
        };
        
    } catch (err) {
        console.error('[CUSTOM KX] Response failed:', err);
        return {
            success: false,
            reason: `Key exchange response failed: ${err.message}`
        };
    }
};

export const customKX_finalizeKeyExchange_initiator = async (
    sessionId,
    kxResponseMsg,
    responseSignature
) => {
    try {
        const { getActiveSession, removeActiveSession, storeEstablishedSessionKeys } = await import('./keyExchangeState');
        const session = getActiveSession(sessionId);
        
        if (!session || session.role !== 'initiator') {
            throw new Error('Invalid session or wrong role');
        }
        
        const responderSigningPubKey = await customKX_importPublicKeyJwk(
            kxResponseMsg.longTermPub,
            'ecdsa'
        );
        
        const responseTranscript = customKX_buildTranscript(kxResponseMsg);
        const signatureValid = await customKX_verifySignature(
            responderSigningPubKey,
            responseTranscript,
            responseSignature
        );
        
        if (!signatureValid) {
            throw new Error('Invalid responder signature');
        }
        
        const responderEphemeralPubKey = await customKX_importPublicKeyJwk(
            kxResponseMsg.ephPub,
            'ecdh'
        );
        
        const sharedSecret = await customKX_deriveSharedSecret(
            session.myEphemeralPrivateKey,
            responderEphemeralPubKey
        );
        
        const sessionKeys = await customKX_hkdfDeriveSessionKeys(sharedSecret);
        
        const fullTranscript = customKX_buildTranscript(session.kxHelloMsg, kxResponseMsg);
        
        const confirmTag = await customKX_computeKeyConfirmation(
            sessionKeys.hmacKey,
            fullTranscript
        );
        
        storeEstablishedSessionKeys(
            session.kxHelloMsg.id,
            session.peerUsername,
            sessionKeys.aesKey,
            sessionKeys.hmacKey
        );
        
        removeActiveSession(sessionId);
        
        return {
            success: true,
            aesKey: sessionKeys.aesKey,
            hmacKey: sessionKeys.hmacKey,
            confirmTag: confirmTag,
            salt: sessionKeys.salt
        };
        
    } catch (err) {
        console.error('[CUSTOM KX] Initiator finalization failed:', err);
        return {
            success: false,
            reason: `Finalization failed: ${err.message}`
        };
    }
};

export const customKX_finalizeKeyExchange_responder = async (sessionId, confirmTag, salt = null) => {
    try {
        const { getActiveSession, removeActiveSession, storeEstablishedSessionKeys } = await import('./keyExchangeState');
        const session = getActiveSession(sessionId);
        
        if (!session || session.role !== 'responder') {
            throw new Error('Invalid session or wrong role');
        }
        
        const initiatorEphemeralPubKey = await customKX_importPublicKeyJwk(
            session.kxHelloMsg.ephPub,
            'ecdh'
        );
        
        const sharedSecret = await customKX_deriveSharedSecret(
            session.myEphemeralPrivateKey,
            initiatorEphemeralPubKey
        );
        
        const saltBuffer = salt ? base64ToArrayBuffer(salt) : null;
        const sessionKeys = await customKX_hkdfDeriveSessionKeys(sharedSecret, saltBuffer);
        
        const fullTranscript = customKX_buildTranscript(
            session.kxHelloMsg,
            session.kxResponseMsg
        );
        
        const confirmValid = await customKX_verifyKeyConfirmation(
            sessionKeys.hmacKey,
            fullTranscript,
            confirmTag
        );
        
        if (!confirmValid) {
            throw new Error('Invalid confirmation tag');
        }
        
        storeEstablishedSessionKeys(
            session.kxResponseMsg.id,
            session.peerUsername,
            sessionKeys.aesKey,
            sessionKeys.hmacKey
        );
        
        removeActiveSession(sessionId);
        
        return {
            success: true,
            aesKey: sessionKeys.aesKey,
            hmacKey: sessionKeys.hmacKey
        };
        
    } catch (err) {
        console.error('[CUSTOM KX] Responder finalization failed:', err);
        return {
            success: false,
            reason: `Finalization failed: ${err.message}`
        };
    }
};

