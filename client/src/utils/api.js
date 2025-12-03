  
import { API_URL } from './config';

export const logSecurityEvent = async (type, details, token = null) => {
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

export const registerUser = async (username, password, publicKey, longTermSigningPublicKey) => {
  const res = await fetch(`${API_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, publicKey, longTermSigningPublicKey })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Registration failed');
  
  return data;
};

export const loginUser = async (username, password) => {
  const res = await fetch(`${API_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Login failed');
  
  return data;
};

export const fetchLogs = async (token) => {
  const res = await fetch(`${API_URL}/logs`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch logs');
  return data;
};

export const fetchUsers = async (token) => {
  const res = await fetch(`${API_URL}/users`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch users');
  return data;
};

export const fetchUserPublicKey = async (username, token) => {
  try {
    const res = await fetch(`${API_URL}/users/${username}/public-key`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) return data;
    return null;
  } catch (err) {
    console.error("Fetch public key failed", err);
    return null;
  }
};

export const sendMessage = async (messageData, token) => {
  const res = await fetch(`${API_URL}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify(messageData)
  });
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Failed to send message');
  
  return data;
};

export const fetchMessages = async (otherUsername, token) => {
  const res = await fetch(`${API_URL}/messages/${otherUsername}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error('Failed to fetch messages');
  return data;
};

export const uploadEncryptedFile = async (fileMetadata, recipientUsername, token) => {
  try {
    const res = await fetch(`${API_URL}/files/upload`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        ...fileMetadata,
        recipientUsername
      })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File upload failed');
    
    console.log(`[FILE_SHARING] File uploaded successfully. ID: ${data.fileId}`);
    return data;
  } catch (err) {
    console.error("File upload failed:", err);
    throw new Error("Failed to upload encrypted file");
  }
};

export const fetchSharedFiles = async (token) => {
  try {
    const res = await fetch(`${API_URL}/files`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch shared files');
    
    console.log(`[FILE_SHARING] Retrieved ${data.length || 0} shared files`);
    return data;
  } catch (err) {
    console.error("Fetch shared files failed:", err);
    throw new Error("Failed to fetch shared files");
  }
};

export const downloadEncryptedFile = async (fileId, token) => {
  try {
    const res = await fetch(`${API_URL}/files/download/${fileId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File download failed');
    
    console.log(`[FILE_SHARING] Downloaded encrypted file: ${fileId}`);
    return data;
  } catch (err) {
    console.error("File download failed:", err);
    throw new Error("Failed to download encrypted file");
  }
};

export const deleteSharedFile = async (fileId, token) => {
  try {
    const res = await fetch(`${API_URL}/files/${fileId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'File deletion failed');
    
    console.log(`[FILE_SHARING] File deleted: ${fileId}`);
    return data;
  } catch (err) {
    console.error("File deletion failed:", err);
    throw new Error("Failed to delete file");
  }
};

export const logFileSharingEvent = async (eventType, details, token) => {
  try {
    await fetch(`${API_URL}/log`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        type: eventType,
        details,
        level: 'info'
      })
    });
  } catch (err) {
    console.error("Failed to log file sharing event:", err);
  }
};


export const sendKXHello = async (sessionId, kxHelloMsg, helloSignature, responder, token) => {
    const res = await fetch(`${API_URL}/key-exchange/hello`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({
            sessionId,
            kxHelloMsg,
            helloSignature,
            responder
        })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to send KX_HELLO');
    return data;
};

export const fetchPendingKeyExchanges = async (token) => {
    const res = await fetch(`${API_URL}/key-exchange/pending`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch pending key exchanges');
    return data;
};

export const sendKXResponse = async (sessionId, kxResponseMsg, responseSignature, token) => {
    const res = await fetch(`${API_URL}/key-exchange/response`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({
            sessionId,
            kxResponseMsg,
            responseSignature
        })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to send KX_RESPONSE');
    return data;
};

export const fetchKXResponse = async (sessionId, token) => {
    const res = await fetch(`${API_URL}/key-exchange/response/${sessionId}`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch KX_RESPONSE');
    return data;
};

export const sendKXConfirm = async (sessionId, confirmTag, salt, token) => {
    const res = await fetch(`${API_URL}/key-exchange/confirm`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({
            sessionId,
            confirmTag,
            salt
        })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to send KX_CONFIRM');
    return data;
};

export const fetchKXConfirm = async (sessionId, token) => {
    const res = await fetch(`${API_URL}/key-exchange/confirm/${sessionId}`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch KX_CONFIRM');
    return data;
};

export const fetchUserSigningPublicKey = async (username, token) => {
    const res = await fetch(`${API_URL}/users/${username}/signing-public-key`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error('Failed to fetch signing public key');
    return data;
};
