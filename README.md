# Encrypted Social Space (CSE447 Lab Project)

A social platform where users post needs (requests for help, items, services), comment publicly, and message privately in real time. Every sensitive field is encrypted before it reaches the database. This project is intentionally built with custom crypto primitives (no framework crypto for encryption) to satisfy academic requirements.

## Features

- Public feed with encrypted posts and comments
- Public profiles with encrypted fields
- Real-time direct messaging (Socket.IO)
- Role-based access control (user/admin)
- Custom JWT access + refresh tokens (httpOnly cookies)
- Key management with rotation and versioning
- HMAC integrity checks on every encrypted document

## Tech Stack

- Frontend: Next.js 14 (App Router, ESM)
- Backend: Express.js (Node 18+, ESM)
- Real-time: Socket.IO
- Database: MongoDB + Mongoose
- File uploads: UploadThing

## Encryption Overview

This project uses **asymmetric encryption only**. No symmetric ciphers are used.

**Algorithms used**

- RSA-OAEP (2048-bit): posts, comments, messages, 2FA secrets
- ECC/ECIES (secp256k1): registration data and profile fields
- HMAC-SHA256: integrity for every encrypted document

**How encryption is applied**

- User identity fields (username, email, contact) are ECC-encrypted before storage.
- 2FA secrets are RSA-encrypted before storage.
- Posts and comments are RSA-encrypted and chunked to fit RSA limits.
- Direct messages are double-encrypted: once for the sender, once for the recipient (no shared symmetric key).
- Every encrypted document stores an HMAC signature; reads verify the MAC before decrypting.

## Run Locally

### Prerequisites

- Node.js 18+
- MongoDB connection string

### Install

```bash
# backend
cd server
npm install

# frontend
cd ../web
npm install
```

### Environment Variables

Create the following files:

**server/.env**

```env
PORT=5000
NODE_ENV=development
MONGO_URI=your_mongodb_uri

JWT_SECRET=your_jwt_secret_hex
JWT_REFRESH_SECRET=your_refresh_secret_hex
HMAC_SERVER_KEY=your_hmac_key_hex

SERVER_RSA_PUBLIC_KEY=base64_pem
SERVER_RSA_PRIVATE_KEY=base64_pem
SERVER_ECC_PUBLIC_KEY=base64_point
SERVER_ECC_PRIVATE_KEY=base64_scalar

CLIENT_ORIGIN=http://localhost:3000
```

**web/.env.local**

```env
UPLOADTHING_TOKEN=...
NEXT_PUBLIC_API_URL=http://localhost:5000/api
NEXT_PUBLIC_SOCKET_URL=http://localhost:5000
```

### Start Dev Servers

```bash
# backend
cd server
npm run dev

# frontend
cd ../web
npm run dev
```

- API: http://localhost:5000
- Web: http://localhost:3000

## Project Structure

```
.
├── CLAUDE.MD                # Source-of-truth project spec
├── README.md                # This file
├── server/                  # Express.js API server
│   ├── app.js
│   ├── index.js
│   ├── controllers/
│   ├── crpyto/              # Custom crypto (RSA, ECC, HMAC, hash)
│   ├── middlewares/
│   ├── models/
│   ├── routes/
│   ├── scripts/
│   ├── services/
│   ├── socket/
│   └── utils/
└── web/                     # Next.js 14 App Router
    ├── app/
    ├── components/
    ├── lib/
    │   └── crypto/          # Client-side crypto mirror
    ├── public/
    └── utils/
```

## Security Notes

- No built-in encryption libraries (no `crypto.subtle`, `crypto` module, or `bcrypt`).
- All sensitive fields are encrypted before storage and decrypted on read.
- Access tokens are short-lived; refresh tokens are stored as httpOnly cookies.
- Key versioning supports re-encryption after rotation.

## Useful Docs

- Project spec and requirements: `CLAUDE.MD`
- Frontend README: `web/README.md`
