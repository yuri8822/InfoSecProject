# STRIDE Threat Modeling – InfoSecProject

This document captures a tailored STRIDE analysis for the InfoSecProject end-to-end encrypted messaging system. It highlights the critical assets, enumerates threats, pinpoints vulnerable components, and maps each threat to the countermeasures implemented in the codebase.

---

## 1. System Overview

| Component | Description | Key Assets |
|-----------|-------------|------------|
| Client (React/Vite) | Handles registration, login, key generation/storage, chat UI, replay/mitm demos | RSA private keys (IndexedDB), session tokens, encrypted messages/files |
| Server (Express/MongoDB) | Provides auth, message/file routing, audit logging | User records, public keys, JWTs, audit logs, encrypted payload storage |
| Network Channel | HTTPS REST API between client and server | Confidentiality/integrity of API calls, protection against MITM |

---

## 2. STRIDE Analysis

### Spoofing
| Threat | Vulnerable Component | Countermeasures | Evidence / References |
|--------|---------------------|-----------------|------------------------|
| An attacker impersonates another user to obtain messages or files. | Login endpoint (`/api/login`), session handling. | BCrypt password hashing, JWT-based auth, server-side verification on every API call, client stores tokens locally with logout clearing them. | `server/routes.js` (login, JWT verify), `client/src/App.jsx` (session management). |
| MITM attacker spoofs key exchange partner to decrypt messages. | Chat key exchange (client-side). | Custom ECDH protocol with long-term ECDSA signatures, HKDF, HMAC confirmation; demo in `MitmAttackDemo` proves spoofing fails with signatures. | `client/src/utils/crypto.js` (`customKX_*`), `client/src/components/MitmAttackDemo.jsx`. |

### Tampering
| Threat | Vulnerable Component | Countermeasures | Evidence |
|--------|---------------------|-----------------|----------|
| Encrypted message or file contents altered in transit. | Network channel, message store. | AES-256-GCM provides integrity (auth tag). Server never decrypts data; tampering triggers `decryptAES`/`decryptFileChunk` errors and audit logs. | `client/src/utils/crypto.js` (`encryptAES`, `decryptAES`, file chunk functions). |
| Replay or sequence tampering. | Message persistence (`Message` model). | Nonce + sequence number validation + timestamp freshness checks on server; client logs replay attempts. | `server/routes.js` (replay checks). |

### Repudiation
| Threat | Vulnerable Component | Countermeasures | Evidence |
|--------|---------------------|-----------------|----------|
| Malicious user denies performing a sensitive action. | Security logging/auditing pipeline. | Centralized audit logs stored in MongoDB with type, timestamp, user, IP; client reports events via `/api/log`. Demo components also log detections. | `server/server.js` (`logSchema`, `createLog`), `client/src/utils/api.js` (`logSecurityEvent`). |

### Information Disclosure
| Threat | Vulnerable Component | Countermeasures | Evidence |
|--------|---------------------|-----------------|----------|
| Server operators access plaintext chats/files. | Message/file storage. | All content encrypted client-side; server stores ciphertext + encrypted AES keys. | `server/routes.js` (messages/files store encrypted data only). |
| Loss of user private key leads to disclosure on other device. | Key storage (client). | Private keys generated via Web Crypto and stored in IndexedDB; never sent to server; warning logged if key missing on login. | `client/src/utils/indexedDB.js`, `client/src/App.jsx` (KEY_WARNING). |
| MITM on network reveals plaintext. | Network layer. | HTTPS (CORS origin locked), plus custom signed ECDH; MITM demo proves defense. | `server/server.js` (CORS), `MitmAttackDemo.jsx`. |

### Denial of Service
| Threat | Vulnerable Component | Countermeasures | Evidence |
|--------|---------------------|-----------------|----------|
| Flood of replayed messages/duplicate nonces to exhaust storage. | `/api/messages` | Replay detection (nonce uniqueness, sequence order, timestamp window). Offenders logged as `REPLAY_ATTACK_DETECTED`. | `server/routes.js`. |
| Large encrypted file uploads exhaust server memory. | `/api/files/upload` | Body size limited (`express.json({ limit: '100mb' })`), chunk metadata stored; logs capture abnormal usage. | `server/server.js`, `client/src/components/FileSharing.jsx`. |

### Elevation of Privilege
| Threat | Vulnerable Component | Countermeasures | Evidence |
|--------|---------------------|-----------------|----------|
| Unauthorized user invokes admin-only actions. | API routing. | Every protected route requires JWT, and server extracts username from token before DB queries. No client-provided role accepted blindly. | `server/routes.js` (`authHeader` checks). |
| Attacker injects keys to hijack sessions. | Key exchange & message encryption. | Only long-term signed keys accepted; server public-key fetch endpoint logs each access; client caches keys locally and validates presence before chat. | `customKX_performKeyExchange`, `client/src/App.jsx` (public key fetch + caching). |

---

## 3. Threat-to-Defense Mapping Summary

| STRIDE Category | Primary Defenses Implemented |
|-----------------|------------------------------|
| Spoofing | JWT auth, signed ECDH, audit logs for key fetch, MITM detection logging |
| Tampering | AES-GCM integrity, server-side nonce/sequence checks, file chunk auth tags |
| Repudiation | Detailed audit logs (`createLog`), client security event reporting |
| Information Disclosure | Client-side encryption (messages/files), private key confinement to IndexedDB, key-warning alerts |
| Denial of Service | Request limits, replay checks, chunked uploads, monitoring via logs |
| Elevation of Privilege | JWT verification before every route, strict role assumptions (no client-provided roles), signed key exchange |

---

## 4. Future Hardening Ideas

- Integrate rate limiting/IP blocking for repeated replay or MITM detections.
- Add certificate pinning or WebAuthn-backed key attestation to strengthen spoofing resistance.
- Automate log ingestion into SIEM for repudiation-proof alerting.
- Extend STRIDE review to CI/CD assets (deploy scripts, environment secrets).

---

**Document references:**  
- Custom crypto protocol: `client/src/utils/crypto.js`  
- MITM demo: `client/src/components/MitmAttackDemo.jsx`  
- Replay protection: `server/routes.js` & `client/src/components/ReplayAttackDemo.jsx`


