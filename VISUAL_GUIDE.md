# End-to-End Encrypted File Sharing - Visual Guide

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENDER (Alice)                           │
│                                                                 │
│  1. Select file: "document.pdf"                                │
│  2. Enter recipient: "bob"                                     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Client-Side Encryption Process                          │ │
│  │                                                          │ │
│  │  document.pdf (5MB)                                     │ │
│  │        │                                                │ │
│  │        ├─→ Fetch Bob's RSA PUBLIC key from server      │ │
│  │        │   (Server trusts Bob's key)                   │ │
│  │        │                                                │ │
│  │        ├─→ Generate random AES-256 session key         │ │
│  │        │                                                │ │
│  │        ├─→ Split into chunks (5MB each)                │ │
│  │        │   ┌─ Chunk 1 (5MB)                            │ │
│  │        │   │ Encrypt with AES-256-GCM + random IV     │ │
│  │        │   │ → Encrypted Chunk 1                       │ │
│  │        │   │                                            │ │
│  │        │   └─ Result: {ciphertext, iv, authTag}       │ │
│  │        │      (32 bytes metadata per chunk)            │ │
│  │        │                                                │ │
│  │        └─→ Encrypt AES session key                     │ │
│  │            RSA-OAEP(AES key, Bob's public key)        │ │
│  │            → Encrypted AES Key                         │ │
│  │                                                          │ │
│  │  Result: {                                              │ │
│  │    fileName: "document.pdf",                           │ │
│  │    fileSize: 5242880,                                  │ │
│  │    encryptedAESKey: "...",  ← Only Bob can decrypt   │ │
│  │    encryptedChunks: [                                 │ │
│  │      { chunkIndex: 0, ciphertext: "...", iv, tag }   │ │
│  │    ]                                                    │ │
│  │  }                                                       │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
│  3. Upload to server (already encrypted)                       │
│     POST /api/files/upload                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ (Encrypted data only)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SERVER (Untrusted)                         │
│                                                                 │
│  Store File Document:                                          │
│  {                                                              │
│    _id: "file-123",                                           │
│    fileName: "document.pdf",                                  │
│    from: "alice",                                             │
│    to: "bob",                                                 │
│    totalChunks: 1,                                            │
│    chunkSize: 5242880,                                        │
│    encryptedAESKey: "...RSA-encrypted...",    ✗ Cannot read  │
│    encryptedChunks: [{                         ✗ Cannot decrypt
│      chunkIndex: 0,                                           │
│      ciphertext: "...AES-encrypted...",                      │
│      iv: "...random IV (Base64)...",                         │
│      authTag: "...authentication tag..."                     │
│    }],                                                         │
│    uploadedAt: "2025-12-02T10:30:00Z",                       │
│    expiresAt: "2026-01-01T10:30:00Z"  ← Auto-delete         │
│  }                                                              │
│                                                                 │
│  Audit Log:                                                    │
│  {                                                              │
│    type: "FILE_UPLOADED",                                    │
│    details: "File uploaded from alice to bob",              │
│    timestamp: "2025-12-02T10:30:00Z",                        │
│    severity: "info"                                           │
│  }                                                              │
│                                                                 │
│  ⚠️  Server CANNOT:                                            │
│      - Decrypt encryptedAESKey (no RSA private key)          │
│      - Decrypt encryptedChunks (doesn't have AES key)        │
│      - Access file contents                                   │
│      - Modify file (authTag would fail validation)           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ Bob wants file
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      RECIPIENT (Bob)                            │
│                                                                 │
│  1. View shared files: GET /api/files                          │
│     Returns: [ {fileName, fileSize, from, ...} ]              │
│                                                                 │
│  2. Click Download on "document.pdf from alice"               │
│                                                                 │
│  3. Download encrypted file: GET /api/files/download/123      │
│     Downloads:                                                 │
│     {                                                           │
│       encryptedAESKey: "...",                                 │
│       encryptedChunks: [{ ciphertext, iv, authTag }],        │
│       ...                                                       │
│     }                                                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Client-Side Decryption Process                          │ │
│  │                                                          │ │
│  │  1. Retrieve Bob's RSA PRIVATE key from device storage  │ │
│  │     (Never left device, never sent to server)          │ │
│  │                                                          │ │
│  │  2. Decrypt AES session key:                            │ │
│  │     AES key = RSA-OAEP.decrypt(                         │ │
│  │       encryptedAESKey,                                  │ │
│  │       Bob's private key                                │ │
│  │     )                                                    │ │
│  │                                                          │ │
│  │  3. For each encrypted chunk:                           │ │
│  │     plaintext = AES-256-GCM.decrypt(                   │ │
│  │       ciphertext,                                       │ │
│  │       iv,                                               │ │
│  │       authTag,  ← Validates authenticity               │ │
│  │       AES key                                           │ │
│  │     )                                                    │ │
│  │                                                          │ │
│  │  4. Concatenate all decrypted chunks:                   │ │
│  │     document.pdf = chunk[0] + chunk[1] + ...           │ │
│  │                                                          │ │
│  │  5. Create blob and download:                           │ │
│  │     const blob = new Blob([data])                      │ │
│  │     const url = URL.createObjectURL(blob)             │ │
│  │     downloadLink.click()                               │ │
│  │                                                          │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
│  6. File saved: ~/Downloads/document.pdf                       │
│     ✅ Same as original, fully decrypted                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Encryption/Decryption Flow

### Upload Flow: AES-256-GCM Chunking

```
Original File (20MB)
│
├─ Split into chunks (5MB each)
│
├─ Chunk 1 (5MB)
│  ├─ Generate random IV (96-bit)
│  ├─ Encrypt with AES-256-GCM
│  └─ Extract Auth Tag (128-bit)
│  └─ Result: {ciphertext, iv, authTag}
│
├─ Chunk 2 (5MB)
│  └─ [Same process with NEW random IV]
│
├─ Chunk 3 (5MB)
│  └─ [Same process with NEW random IV]
│
├─ Chunk 4 (5MB)
│  └─ [Same process with NEW random IV]
│
└─ Encrypt AES key with RSA
   └─ RSA-OAEP(AES key, recipient's public key)
   └─ Result: encryptedAESKey
```

**Benefits of Chunking:**
- 💾 Memory efficient (don't load entire 20MB file)
- 🌐 Network friendly (can retry individual chunks)
- 📊 Random IV per chunk = different ciphertext even for same data
- ⚡ Can encrypt/decrypt in parallel

### Download Flow: Decryption

```
Encrypted File from Server
│
├─ Decrypt AES key (using private RSA key)
│  └─ AES key = RSA.decrypt(encryptedAESKey, my_private_key)
│
├─ Decrypt Chunk 1
│  ├─ plaintext = AES-GCM.decrypt(ciphertext, iv, authTag, aesKey)
│  ├─ ✅ If authTag validates → Chunk 1 is authentic
│  └─ ❌ If authTag fails → Chunk was tampered, abort
│
├─ Decrypt Chunk 2, 3, 4 (same process)
│
└─ Concatenate all chunks
   └─ Original file = Chunk1 + Chunk2 + Chunk3 + Chunk4
```

---

## Key Management

### RSA Key Pair (Generated at Registration)

```
┌─────────────────────────────┐
│  Alice's RSA-2048 Key Pair  │
│                             │
│  Public Key (JWK)           │
│  {                          │
│    kty: "RSA",             │
│    n: "...",               │
│    e: "AQAB",              │
│    ...                      │
│  }                          │
│  ✅ Stored on SERVER       │
│  ✅ Shared with others     │
│                             │
│  PRIVATE KEY               │
│  ❌ NEVER sent to server   │
│  ❌ Stored in browser's    │
│     IndexedDB              │
│  ❌ Protected by browser   │
│  ❌ Only accessible to     │
│     Alice's device         │
└─────────────────────────────┘
```

### AES Session Key (Generated Per File)

```
File Upload:
   Generate new random AES-256 key
   │
   ├─ Use to encrypt file chunks
   │
   └─ Encrypt key with recipient's RSA PUBLIC key
      └─ encryptedAESKey = RSA.encrypt(AES_key, bob_public_key)
      └─ Attach to file metadata

File Download:
   Get encryptedAESKey from server
   │
   ├─ Decrypt with MY private key
   │  └─ AES_key = RSA.decrypt(encryptedAESKey, my_private_key)
   │
   └─ Use AES key to decrypt all chunks
```

---

## Security Properties

### Authentication Tag (GCM)

Each chunk protected by 128-bit authentication tag:

```
Sender encrypts:
  plaintext + key + IV + random data
  │
  └─ AES-256-GCM
  │
  └─ ciphertext + authTag

Receiver decrypts:
  IF authTag validates:
    ✅ Data is authentic
    ✅ Data not modified
    ✅ Can trust plaintext
  
  IF authTag fails:
    ❌ Data was tampered with
    ❌ Abort decryption
    ❌ Alert user
```

### Unique IV per Chunk

```
Two identical chunks encrypted separately:

Chunk 1 data: "This is secret"
  IV: random_value_1
  Result: ciphertext_A

Same Chunk 1 data: "This is secret"
  IV: random_value_2  ← DIFFERENT
  Result: ciphertext_B  ← DIFFERENT

Even with same plaintext:
  Different IV = Different ciphertext = No pattern leakage
```

---

## Attack Scenarios & Mitigations

### Scenario 1: Server Admin Tries to Read Files

```
Attack: Admin accesses MongoDB, reads file documents

Document contains:
  {
    encryptedAESKey: "...",  ← Cannot decrypt (no RSA private key)
    encryptedChunks: [{
      ciphertext: "..."      ← Cannot decrypt (no AES key)
    }]
  }

Result: ❌ FAILED
  Even with full database access, files remain encrypted.
```

### Scenario 2: Man-in-the-Middle Intercepts File

```
Attack: Network attacker intercepts encrypted file

Intercepted data:
  {
    encryptedAESKey: "...",  ← Cannot decrypt (encrypted with Bob's
    encryptedChunks: [...]         public key, only Bob has private)
  }

Result: ❌ FAILED
  Even intercepted, data is encrypted. Attacker gets nothing.
```

### Scenario 3: Attacker Modifies Encrypted Chunk

```
Attack: Attacker changes 1 byte in ciphertext

Original chunk:
  ciphertext: "a1b2c3d4..."
  authTag: "e5f6g7h8..."

Modified chunk:
  ciphertext: "a1b2c3d5..."  ← Changed last nibble
  authTag: "e5f6g7h8..."     ← Still same

Recipient tries to decrypt:
  AES-GCM.decrypt(modified_ciphertext, iv, authTag, key)
  │
  └─ Compute auth tag for modified ciphertext
     │
     └─ Computed authTag: "x1y2z3w4..." ← DIFFERENT
     │
     └─ Doesn't match provided authTag
     │
     └─ ❌ Decryption FAILS
     └─ Alert: "File corrupted or tampered"

Result: ❌ FAILED
  Tampering detected immediately.
```

### Scenario 4: Attacker Tries to Decrypt

```
Attack: Attacker gets encrypted file from server

Attacker has:
  encryptedAESKey: "..."
  encryptedChunks: [...]

Attacker doesn't have:
  ❌ Bob's RSA private key (only Bob has)
  ❌ AES decryption key

Attacker tries RSA-OAEP.decrypt(encryptedAESKey, random_key)
  Result: Garbage output or error

Attacker tries brute force AES-256:
  2^256 possible keys = 10^77 attempts
  At 1 trillion attempts/second = 10^18 years

Result: ❌ FAILED
  Cryptographically secure.
```

### Scenario 5: User Loses Private Key

```
User loses device/clears browser storage

Private key lost ❌
  Cannot decrypt old files
  Cannot receive new encrypted messages
  Files remain encrypted on server forever

Why no recovery?
  - Private key never backed up to server (security feature)
  - Server never has decryption capability
  - User is responsible for backup

Prevention:
  - Implement backup system (encrypted with master password)
  - Multi-device support (sync private key to multiple devices)
  - Currently: Warning message on new device login
```

---

## UI Component Workflow

### FileSharing Component State Machine

```
                    ┌─────────────────┐
                    │   INITIAL STATE │
                    └────────┬────────┘
                             │
                    Load shared files
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │  READY STATE                           │
        │  - Display upload form                 │
        │  - Display files list                  │
        │  - Status: idle                        │
        └─┬────────────────────────────┬─────────┘
          │                            │
          │ Select file               │ Click download
          │ Enter recipient           │
          │ Click upload              │
          │                            │
          ▼                            ▼
    ┌──────────────────┐        ┌──────────────────┐
    │ UPLOADING STATE  │        │ DOWNLOADING STATE│
    │ Status: loading  │        │ Status: loading  │
    │ Progress bar     │        │ Progress bar     │
    └────────┬─────────┘        └────────┬─────────┘
             │                           │
             │ Success                   │ Success
             │                           │
             ▼                           ▼
    ┌──────────────────┐        ┌──────────────────┐
    │ UPLOAD SUCCESS   │        │ DOWNLOAD SUCCESS │
    │ Status: success  │        │ Status: success  │
    │ Show 4s message  │        │ File downloaded  │
    │ Refresh list     │        │ Refresh list     │
    └────────┬─────────┘        └────────┬─────────┘
             │                           │
             └───────────┬───────────────┘
                         │
                         ▼
            Return to READY STATE
            (4 second message timer)
```

---

## Data Flow Diagram

```
┌─────────────────┐
│  React Component│
│   FileSharing   │
└────────┬────────┘
         │
         ├─────────────────────────────────────┬──────────────────────┐
         │                                     │                      │
         ▼                                     ▼                      ▼
   ┌──────────┐                           ┌──────────┐          ┌──────────┐
   │ Encrypt  │                           │  API    │          │ IndexedDB│
   │  Utils   │                           │ Calls   │          │ Storage  │
   └──────────┘                           └──────────┘          └──────────┘
         │                                     │                      │
         ├─ encryptFileForSharing()            ├─ uploadEncrypted()   ├─ getPrivateKey()
         ├─ decryptFileFromSharing()           ├─ downloadEncrypted() └─ getPublicKey()
         ├─ chunkFile()                        ├─ fetchSharedFiles()
         ├─ encryptFileChunk()                 ├─ deleteSharedFile()
         ├─ decryptFileChunk()                 └─ logEvent()
         │
         ▼
    ┌─────────────────────────────┐
    │   Web Crypto API            │
    │  (Browser Standard)         │
    │                             │
    │ - AES-256-GCM              │
    │ - RSA-2048-OAEP            │
    │ - Key generation           │
    │ - Random number generation │
    └────────────┬────────────────┘
                 │
                 ▼
        ┌──────────────────┐
        │  HTTP/HTTPS      │
        │  (Encrypted)     │
        │                  │
        │  + TLS           │
        │  + CORS          │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │  Express Server  │
        │  Routes          │
        │                  │
        │ POST /files/     │
        │ GET /files       │
        │ GET /download/:id│
        │ DELETE /files/:id│
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │   MongoDB        │
        │   Database       │
        │                  │
        │ Files Collection │
        │ (Encrypted data) │
        └──────────────────┘
```

---

## Summary

The end-to-end encrypted file sharing system ensures:

✅ **Only intended recipient can read files**
✅ **Server cannot access file contents**
✅ **Tampering is immediately detected**
✅ **Files are split efficiently with unique per-chunk encryption**
✅ **Private keys never leave user's device**
✅ **Complete audit trail of all operations**
✅ **User-friendly interface with clear security info**

