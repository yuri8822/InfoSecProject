# InfoSec Messaging Project

A secure end-to-end encrypted messaging application with advanced cryptographic features including RSA encryption, ECDSA signing, AES-GCM encryption, and protection against replay attacks. The project demonstrates real-world security implementations and educational attack demonstrations.

## Features

-   **End-to-End Encryption**: Messages encrypted with AES-GCM, keys exchanged via RSA/ECDH
-   **User Authentication**: Secure registration and login with bcrypt password hashing and JWT tokens
-   **Key Exchange Protocol**: Diffie-Hellman key exchange with ECDSA signatures
-   **Replay Attack Protection**: Nonce and sequence number validation
-   **Encrypted File Sharing**: Send encrypted files up to 100MB with automatic expiry
-   **Security Audit Logging**: All authentication and security events logged to MongoDB
-   **Attack Demonstrations**:
    -   MITM (Man-in-the-Middle) attack demo
    -   Replay attack demo with protection visualization

## Tech Stack

**Frontend:**

-   React 19
-   Vite (build tool)
-   Socket.io-client (real-time communication)
-   Axios (HTTP client)
-   Lucide React (icons)

**Backend:**

-   Node.js with Express
-   MongoDB with Mongoose ODM
-   Bcrypt (password hashing)
-   JWT (authentication)
-   CORS support

## Prerequisites

-   Node.js 16+
-   npm or yarn
-   MongoDB Atlas account (free tier) or local MongoDB
-   Git

## Local Setup

### 1. Clone Repository

```bash
git clone https://github.com/yuri8822/InfoSecProject.gitcd InfoSecProject
```

### 2. Environment Configuration

Create `.env` file in the `server/` directory with your configuration values (see Environment Variables section below).

### 3. Install Dependencies

**Backend:**

```bash
cd servernpm install
```

**Frontend:**

```bash
cd clientnpm install
```

### 4. Run Locally

**Option A: Separate Terminals**

Terminal 1 - Backend:

```bash
cd servernpm start
```

Server runs on `http://localhost:5000`

Terminal 2 - Frontend:

```bash
cd clientnpm run dev
```

Frontend runs on `http://localhost:5173`

**Option B: Batch Script (Windows)**

```bash
./run.bat
```

This launches both server and client in separate command windows.

## Deploy on Render

### Step 1: Set Up MongoDB Atlas

1.  Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2.  Create a free account and new cluster
3.  Create a database user (Database Access)
4.  Get connection string: Clusters → Connect → Drivers
5.  Copy the connection string: `mongodb+srv://username:password@cluster.mongodb.net/dbname`

### Step 2: Create Render Services

#### Backend Deployment

1.  Go to [Render Dashboard](https://dashboard.render.com)
    
2.  Click "New +" → "Web Service"
    
3.  Connect your GitHub repository
    
4.  Configure:
    
    -   **Name**: `infosec-backend`
    -   **Environment**: `Node`
    -   **Build Command**: `cd server && npm install`
    -   **Start Command**: `cd server && npm start`
    -   **Instance Type**: Free
5.  Add Environment Variables (see Environment Variables section below).
    
6.  Click "Create Web Service" and wait for deployment
    

#### Frontend Deployment

1.  Click "New +" → "Static Site"
    
2.  Connect your GitHub repository
    
3.  Configure:
    
    -   **Name**: `infosec-frontend`
    -   **Build Command**: `cd client && npm install && npm run build`
    -   **Publish Directory**: `client/dist`
4.  Click "Create Static Site"
    

### Step 3: Update Frontend API Configuration

1.  Open `client/src/utils/config.js`
    
2.  Update with your backend URL:
    
    ```javascript
    const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://your-backend-url.onrender.com/api';export default API_BASE_URL;
    ```
    
3.  Commit and push to GitHub (Render auto-deploys)
    

### Step 4: Verify Deployment

-   Visit your frontend URL
-   Test user registration and login
-   Check Render logs if issues occur

## Security Features Explained

### End-to-End Encryption

-   Messages encrypted with AES-256-GCM (authenticated encryption)
-   Session keys exchanged via RSA-4096 public key encryption
-   Each message has unique IV (Initialization Vector)

### Authentication

-   Passwords hashed with bcrypt (10 salt rounds)
-   JWT tokens for session management (1-hour expiry)
-   Secure token validation on protected routes

### Key Exchange Protocol

-   ECDH (Elliptic Curve Diffie-Hellman) for shared secret derivation
-   ECDSA (Elliptic Curve Digital Signature Algorithm) for signature verification
-   HKDF (HMAC-based Key Derivation Function) for key material expansion

### Replay Attack Protection

-   Nonce-based replay detection
-   Sequence number verification per conversation
-   Timestamp validation

### Audit Logging

-   All authentication attempts logged
-   Security events stored in MongoDB
-   Severity levels: info, warning, critical

## API Endpoints

### Authentication

-   `POST /api/register` - User registration
-   `POST /api/login` - User login

### Messaging

-   `GET /api/users` - Get all users
-   `POST /api/messages` - Send encrypted message
-   `GET /api/messages/:username` - Get conversation history

### Key Management

-   `POST /api/public-key/:username` - Get user's public key
-   `POST /api/key-exchange/hello` - Initiate key exchange
-   `POST /api/key-exchange/response` - Respond to key exchange
-   `POST /api/key-exchange/confirm` - Confirm key exchange

### File Sharing

-   `POST /api/files/upload` - Upload encrypted file
-   `GET /api/files/:fileId` - Download file
-   `GET /api/files/list` - List files for user

### Logging

-   `POST /api/log` - Client-side security event logging
-   `GET /api/audit-logs` - Retrieve audit logs

## Testing

### Local Testing

1.  Open two browser tabs with `http://localhost:5173`
2.  Register two different users (e.g., "alice" and "bob")
3.  Log in with different users in each tab
4.  Send encrypted messages between them
5.  Test file sharing and attack demos

### Demos Available

-   **MITM Attack Demo**: Shows how man-in-the-middle attacks work and countermeasures
-   **Replay Attack Demo**: Demonstrates replay attack attempts and protection mechanisms

## Troubleshooting

Issue

Solution

MongoDB connection fails

Check connection string, ensure IP is whitelisted in MongoDB Atlas

CORS errors

Update `CORS_ORIGIN` in server `.env`

Frontend can't reach backend

Verify backend URL in `client/src/utils/config.js`

Port already in use

Change `PORT` in `.env` or kill process using port 5000

Dependencies missing

Run `npm install` in both `client/` and `server/` directories

## Environment Variables

### Backend (.env in server/)

| Variable | Description |
|----------|-------------|
| `NODE_ENV` | Environment mode (development or production) |
| `PORT` | Server port (default: 5000) |
| `MONGODB_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret key for JWT signing |
| `CORS_ORIGIN` | Allowed frontend URL |

### Frontend (.env in client/)

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | Backend API URL (optional, falls back to config.js) |