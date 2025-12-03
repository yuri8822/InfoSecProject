# MITM (Man-in-the-Middle) Attack Demonstration Guide

## Overview

The MITM Attack Demo component demonstrates how attackers can intercept unprotected key exchanges and how digital signatures prevent these attacks. This is a critical security concept showing the importance of message authentication.

## Key Concepts

### What is a MITM Attack?

A Man-in-the-Middle (MITM) attack occurs when an attacker intercepts and potentially alters communications between two parties without either party knowing.

**Classic Scenario:**
- Alice wants to send secure messages to Bob
- Eve (attacker) positions herself between Alice and Bob
- Eve intercepts all communications and can read, modify, or inject messages

### Why Diffie-Hellman is Vulnerable Without Signatures

Diffie-Hellman (DH) key exchange allows two parties to establish a shared secret over an insecure channel:

**The Process (Simplified):**
1. Alice and Bob agree on parameters: prime (p) and generator (g)
2. Alice generates private key `a`, computes public key `A = g^a mod p`
3. Alice sends her public key `A` to Bob
4. Bob generates private key `b`, computes public key `B = g^b mod p`
5. Bob sends his public key `B` to Alice
6. Both compute shared secret: `secret = g^(a*b) mod p`

**The Vulnerability (No Signatures):**
- When Alice sends her public key `A`, she doesn't prove she's really Alice
- When Bob sends his public key `B`, he doesn't prove he's really Bob
- Eve can intercept both messages and substitute her own keys:
  - Eve intercepts `A`, generates her own private key `e`
  - Eve sends her public key `E` to Bob (claiming to be Alice)
  - Eve intercepts `B`, sends her own public key `E` to Alice (claiming to be Bob)
  - Now: Alice communicates with Eve, Eve communicates with Bob
  - Eve can decrypt all messages between them!

## How Digital Signatures Prevent MITM

**Digital Signatures Add Authentication:**

### Signing Process (Alice)
1. Alice creates a message (her DH public key)
2. Alice computes hash of the message: `H = Hash(message)`
3. Alice encrypts the hash with her PRIVATE key: `Signature = Encrypt(H, AlicePrivateKey)`
4. Alice sends: `[Public Key] + [Signature]`

### Verification Process (Bob)
1. Bob receives: `[Alice's Public Key] + [Signature]`
2. Bob decrypts signature using Alice's PUBLIC key: `H' = Decrypt(Signature, AlicePublicKey)`
3. Bob computes hash of received message: `H = Hash(message)`
4. Bob compares: Does `H == H'`?
   - **YES** → Signature is valid, message is from Alice ✅
   - **NO** → Signature is invalid, message is forged ❌

### Why Eve Can't Forge Signatures

**Eve's Problem:**
- Eve doesn't have Alice's PRIVATE key (it's secret!)
- Eve can't compute a valid signature for her fake public key
- When Bob verifies the signature using Alice's PUBLIC key, it will FAIL
- Bob rejects the message as forged
- **MITM Attack is BLOCKED!** 🛡️

## The MITM Demo Component

### Location
`client/src/components/MITMDemo.jsx`

### Features

#### 1. **MITM Without Digital Signatures**
**Button:** "Attack 1: MITM No Signatures"

This demonstrates how easily MITM attacks succeed when there's no authentication:

```
Step 1: Alice and Bob agree on DH parameters
  p (prime) = 23
  g (generator) = 5

Step 2: Alice generates her key pair
  Alice Private: 6
  Alice Public: 5^6 mod 23 = 8

Step 3: Eve INTERCEPTS Alice's public key (8)

Step 4: Eve generates her own key pair
  Eve Private: 5
  Eve Public (sent to Bob as "Alice"): 5^5 mod 23 = 14

Step 5: Bob generates his key pair
  Bob Private: 9
  Bob Public: 5^9 mod 23 = 2

Step 6: Eve INTERCEPTS Bob's public key (2)

Step 7: Computing shared secrets
  Alice thinks shared key is: 14^6 mod 23 = 9
  Bob thinks shared key is: 14^9 mod 23 = 12
  Eve has: 8^5 mod 23 = 2 (with Alice) and 2^5 mod 23 = 10 (with Bob)
  
Result: Eve can decrypt all messages!
```

**Console Output Shows:**
- Key generation for each party
- How Eve intercepts and substitutes keys
- Three different shared secrets (Eve has two!)
- Clear demonstration of successful MITM

#### 2. **MITM With Digital Signatures**
**Button:** "Attack 2: MITM With Signatures"

This demonstrates how signatures protect against MITM:

```
Step 1: Alice pre-shares her public key with Bob
  (via secure channel or certificate authority)

Step 2: Alice sends signed message
  Public Key: 8
  Signature: RSA-PSS signature of this key

Step 3: Eve attempts to intercept
  Eve has her key: 14
  Eve tries to create a fake signature
  Problem: Eve doesn't have Alice's private key!

Step 4: Bob receives and verifies
  Received Public Key: ???
  Signature: ???
  Bob uses Alice's pre-shared public key to verify
  Valid Alice signature? ✅ YES
  
  If Eve sends her key (14):
  Signature verification fails ❌ NO
  Bob rejects as forged
  MITM attack is blocked!
```

**Console Output Shows:**
- Alice signing her public key
- Eve's failed attempt to forge a signature
- Bob's signature verification process
- Attack blocked with detailed reasoning

#### 3. **How Digital Signatures Work**
**Button:** "How Signatures Work"

Educational demonstration showing:
- Hashing and encryption process
- Sender signing (what Alice does)
- Receiver verification (what Bob does)
- Why attackers can't forge signatures

### Usage

1. **Click Attack Button:**
   - Logs appear in browser console
   - Open DevTools (F12) to see detailed flow

2. **Review Attack Details:**
   - Click on attack result to expand
   - Shows DH parameters
   - Shows key exchange details
   - Shows protection mechanism
   - Shows final result (VULNERABLE vs PROTECTED)

3. **Examine Console Output:**
   - Each attack prints step-by-step explanation
   - Shows mathematical computation details
   - Shows Eve's capabilities and limitations

## Attack Flow Diagrams

### MITM WITHOUT Signatures

```
Alice ←→ Eve ←→ Bob

Alice sends Public Key: 8
  ↓ (Intercepted by Eve)
Eve replaces with: 14
  ↓
Bob receives: 14 (thinks it's Alice)

Bob sends Public Key: 2
  ↓ (Intercepted by Eve)
Eve replaces with: 14
  ↓
Alice receives: 14 (thinks it's Bob)

Result:
- Alice encrypts with key 9 (derived from 14)
- Eve decrypts with key 2 (derived from 8 and 14)
- Eve re-encrypts with key 10 (derived from 2 and 14)
- Bob decrypts with key 12 (derived from 14)

All messages between Alice and Bob can be read by Eve!
```

### MITM WITH Signatures (Protected)

```
Alice ←→ Eve ←→ Bob

Alice sends:
  [Public Key: 8]
  [Signature: Sign(8, AlicePrivateKey)]
  ↓ (Intercepted by Eve)
  
Eve wants to replace with:
  [Public Key: 14]
  [Signature: ???]
  
Problem: Eve can't create valid signature without Alice's private key!

Bob receives and verifies signature:
  Decrypt(Signature, AlicePublicKey) matches Hash(8)?
  ✅ YES - Message accepted from Alice
  
If Eve sends her key:
  Decrypt(FakeSignature, AlicePublicKey) matches Hash(14)?
  ❌ NO - Signature invalid, message rejected
  
Result: MITM attack detected and blocked! 🛡️
```

## Integration with Project

### Files Modified
1. **`client/src/components/MITMDemo.jsx`** (NEW)
   - Main MITM attack demonstration component
   - 872 lines of code
   - Three attack demonstrations

2. **`client/src/components/Dashboard.jsx`** (MODIFIED)
   - Added MITM Demo button
   - Integrated onShowMITMDemo callback

3. **`client/src/App.jsx`** (MODIFIED)
   - Added MITMDemo import
   - Added mitm-demo view state
   - Added MITM demo modal display

### Component Props

```javascript
<MITMDemo currentUser={username} />
```

**Props:**
- `currentUser` (string): Username of currently logged-in user
- Displays attacker as "alice" and victim as logged-in user

### View Switching

**From Dashboard:**
```
Dashboard → Click "MITM Demo" button → MITMDemo Modal
MITMDemo Modal → Click "Back to Dashboard" → Dashboard
```

## Security Concepts Demonstrated

### 1. Key Exchange Vulnerability
- Unauthenticated key exchange is vulnerable to MITM
- Attackers can impersonate both parties
- No way to detect the attack is happening

### 2. Digital Signatures Solution
- Signatures prove message authenticity
- Receivers can verify sender identity
- Attackers can't forge signatures without private keys

### 3. Mathematical Security
- RSA signatures are mathematically secure
- Private keys can't be derived from public keys
- Computationally infeasible to forge signatures

### 4. Pre-Shared Trust
- Both parties must have each other's public keys beforehand
- Or: Must use trusted certificate authority (CA)
- Signature verification depends on trusting the public key

## Real-World Applications

### HTTPS/TLS
- Uses digital certificates (RSA signatures)
- Protects against MITM attacks
- Certificates signed by trusted Certificate Authorities

### SSH
- Uses public key authentication
- Verifies server identity with digital signatures
- Prevents MITM attacks on initial connection

### PGP/GPG
- Users sign messages with private keys
- Recipients verify signatures with public keys
- Protects against message tampering and impersonation

## Extended Implementation (Not in Current Demo)

For production-grade MITM protection, add:

1. **Diffie-Hellman Implementation**
   ```javascript
   generateDHKeyPair()  // Generate prime, generator, private key
   computeSharedSecret()  // Compute g^(a*b) mod p
   ```

2. **Digital Signature Implementation**
   ```javascript
   signMessage(message, privateKey)    // Sign with RSA-PSS
   verifySignature(message, signature, publicKey)  // Verify signature
   ```

3. **Server Endpoints**
   ```
   POST /api/dh/initiate     // Start DH key exchange
   POST /api/dh/complete     // Send DH public key + signature
   GET /api/users/:user/public-key  // Retrieve pre-shared public key
   ```

## Running the Demo

1. **Start the application:**
   ```bash
   npm install && npm run dev
   ```

2. **Login as any user** (alice, bob, charlie, diana, eve)

3. **Click "MITM Demo" button** on Dashboard

4. **Click attack buttons:**
   - "Attack 1: MITM No Signatures"
   - "Attack 2: MITM With Signatures"
   - "How Signatures Work"

5. **View console output** (F12 → Console tab)

6. **Review attack details** by clicking on each result

## Key Takeaways

✅ **Diffie-Hellman without signatures = VULNERABLE to MITM**
- Attackers can intercept and modify key exchanges
- No way to verify key authenticity
- Full compromise of message confidentiality and integrity

✅ **Digital signatures protect against MITM**
- Signatures prove sender identity
- Attackers can't forge signatures
- MITM attacks are detected and blocked

✅ **Trust is essential**
- Both parties need pre-shared public keys
- OR: Must trust Certificate Authority
- Signature verification depends on trusting the public key

✅ **Multiple layers of security needed**
- Confidentiality (encryption)
- Integrity (signatures)
- Authentication (verified identities)
- Together these defeat MITM attacks

## Summary

The MITM Attack Demo component provides a comprehensive, educational demonstration of:
1. How unprotected key exchanges are vulnerable
2. How attackers can intercept and modify communications
3. How digital signatures add authentication
4. Why signatures prevent MITM attacks
5. Mathematical reasons attackers can't forge signatures

This directly addresses **Requirement #7: MITM Attack Demonstration** and provides both visual evidence and detailed technical explanations of MITM attack mechanics and protection mechanisms.
