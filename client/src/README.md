# Client Structure

This directory contains the frontend code for the InfoSec Project, organized by separation of concerns.

## Directory Structure

```
client/src/
├── App.jsx                 # Main application component
├── main.jsx               # Application entry point
├── components/            # Reusable UI components
│   ├── AuthForm.jsx      # Login/Register form component
│   └── Dashboard.jsx     # Main dashboard component
└── utils/                # Utility functions organized by feature
    ├── config.js         # Configuration and environment variables
    ├── crypto.js         # Part 1: Cryptography (RSA-OAEP key generation)
    ├── indexedDB.js      # Part 8: Key Storage (IndexedDB operations)
    └── api.js            # Part 2: Authentication & API calls
```

## Project Parts Implementation

### Part 1: Cryptography
**File:** `utils/crypto.js`
- RSA-OAEP 2048-bit key pair generation
- Key export to JWK format

### Part 2: Authentication
**File:** `utils/api.js`
- User registration and login
- JWT token management
- Security event logging
- API communication with backend

### Part 8: Key Storage
**File:** `utils/indexedDB.js`
- Secure client-side storage using IndexedDB
- Private key storage and retrieval
- Browser-based sandboxed storage

## Components

### AuthForm
Handles both login and registration UI with:
- Form validation
- Error display
- View switching between login/register

### Dashboard
Main application interface showing:
- User directory (registered users)
- Key management panel (storage status)
- Security audit logs (real-time server logs)

## Usage

All utility functions are exported and imported as needed:

```javascript
// Crypto operations
import { generateKeyPair, exportKey } from './utils/crypto';

// Key storage
import { storePrivateKey, getPrivateKey } from './utils/indexedDB';

// API calls
import { registerUser, loginUser, fetchLogs } from './utils/api';
```

## Environment Variables

Configuration is managed through `.env` file:
- `VITE_API_URL`: Backend API URL (default: http://localhost:5000/api)

## Future Additions

As you implement more parts of the project, add corresponding utility files:
- `utils/encryption.js` - Part 3: Message encryption/decryption
- `utils/messaging.js` - Part 4: WebSocket messaging
- `utils/replay.js` - Part 5: Replay attack prevention
- etc.
