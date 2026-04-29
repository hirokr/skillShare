# CLAUDE.md — CSE447 Lab Project
## Encrypted Social Space

> This file is the single source of truth for the entire project.
> Every architectural decision, security rule, data flow, and file responsibility is documented here.
> Read this before touching any file.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack](#2-tech-stack)
3. [Project Structure](#3-project-structure)
4. [Security Architecture](#4-security-architecture)
5. [Encryption Strategy — The 6 Features](#5-encryption-strategy--the-6-features)
6. [Crypto Engine — From Scratch Rules](#6-crypto-engine--from-scratch-rules)
7. [Data Flow — Every Major Operation](#7-data-flow--every-major-operation)
8. [Database Models](#8-database-models)
9. [Backend — File-by-File Responsibilities](#9-backend--file-by-file-responsibilities)
10. [Frontend — File-by-File Responsibilities](#10-frontend--file-by-file-responsibilities)
11. [RBAC — Role-Based Access Control](#11-rbac--role-based-access-control)
12. [Session & Token Management](#12-session--token-management)
13. [Key Management Module](#13-key-management-module)
14. [Real-Time Messaging](#14-real-time-messaging)
15. [Environment Variables](#15-environment-variables)
16. [Important Rules & Constraints](#16-important-rules--constraints)

---

## 1. Project Overview

A social platform where users post their **needs** (requests for help, items, services) and other users can respond by commenting publicly or messaging privately in real-time. Every piece of sensitive data is encrypted before it touches the database.

### Core Features
- User registration and login with two-factor authentication (2FA)
- Public feed of posts (needs/requests) with comments
- Public user profiles
- Real-time direct messaging between any two users
- Role-based access control (admin vs user)
- Full asymmetric encryption on all sensitive data — no symmetric encryption allowed

### Academic Requirements Checklist
- [x] Login and Registration modules
- [x] All user info encrypted (ECC) before storage, decrypted on retrieval
- [x] Passwords hashed and salted (custom implementation)
- [x] Two-step authentication (2FA via TOTP + RSA-encrypted secret)
- [x] Key Management Module (KeyStore model + keyManager service)
- [x] Posts, comments, messages all encrypted before storage
- [x] All critical data stored in encrypted form
- [x] MAC (HMAC-SHA256) on every encrypted document
- [x] Two different asymmetric algorithms: RSA-OAEP and ECC/ECIES
- [x] RBAC with admin and user roles
- [x] Secure session management (JWT + httpOnly cookies + refresh tokens)
- [x] All crypto implemented from scratch — no framework crypto functions

---

## 2. Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | Next.js 14 (App Router, ESM) | UI, routing, client-side key ops |
| Backend | Express.js (ESM, Node 18+) | REST API, business logic |
| Real-time | Socket.IO | Live DM delivery |
| Database | MongoDB + Mongoose | Encrypted document storage |
| File storage | UploadThing | Profile pictures, post media |
| Auth tokens | JWT (custom signing) | Session identity |
| Package type | `"type": "module"` on both frontend and backend | ES modules throughout |

---

## 3. Project Structure

```
project-root/
│
├── CLAUDE.md                          ← You are here
│
├── backend/                           ← Express.js API server
│   ├── package.json                   ← "type": "module"
│   ├── server.js                      ← Entry point, Express + Socket.IO init
│   ├── app.js                         ← Express app config, middleware mounting
│   │
│   ├── config/
│   │   ├── db.js                      ← MongoDB connection
│   │   └── env.js                     ← Validated env vars (throws if missing)
│   │
│   ├── crypto/                        ← ALL custom crypto — no npm crypto libs
│   │   ├── rsa.js                     ← RSA key generation, encrypt, decrypt
│   │   ├── ecc.js                     ← ECC key generation, ECIES encrypt/decrypt
│   │   ├── hmac.js                    ← HMAC-SHA256 from scratch
│   │   ├── hash.js                    ← Password hashing: custom PBKDF2-like
│   │   └── utils.js                   ← BigInt helpers, base64, hex converters
│   │
│   ├── models/
│   │   ├── index.js                   ← Re-exports all models
│   │   ├── User.js                    ← Auth + key pair storage
│   │   ├── Post.js                    ← Encrypted post content
│   │   ├── Comment.js                 ← Encrypted comment content
│   │   ├── Message.js                 ← Conversation + Message (double-encrypted)
│   │   ├── Profile.js                 ← Encrypted extended profile fields
│   │   └── KeyStore.js                ← Key lifecycle management
│   │
│   ├── services/
│   │   ├── authService.js             ← Register, login, 2FA logic
│   │   ├── postService.js             ← Post CRUD + encryption calls
│   │   ├── commentService.js          ← Comment CRUD + encryption calls
│   │   ├── messageService.js          ← DM create/read + double-encryption
│   │   ├── profileService.js          ← Profile read/update + ECC encryption
│   │   └── keyManager.js             ← Key generation, rotation, distribution
│   │
│   ├── middleware/
│   │   ├── authenticate.js            ← JWT verification, attaches req.user
│   │   ├── authorize.js               ← RBAC role check factory
│   │   ├── verifyMac.js               ← HMAC integrity check on incoming data
│   │   └── rateLimiter.js             ← Basic request rate limiting
│   │
│   ├── routes/
│   │   ├── auth.js                    ← POST /register, /login, /logout, /refresh, /2fa
│   │   ├── posts.js                   ← GET/POST/PATCH/DELETE /posts
│   │   ├── comments.js                ← GET/POST/DELETE /posts/:id/comments
│   │   ├── messages.js                ← GET/POST /messages, /conversations
│   │   ├── profiles.js                ← GET/PATCH /profiles/:username
│   │   └── keys.js                    ← POST /keys/rotate, GET /keys/public/:userId
│   │
│   └── sockets/
│       └── messageSocket.js           ← Socket.IO event handlers for real-time DMs
│
└── frontend/                          ← Next.js 14 App Router
    ├── package.json                   ← "type": "module"
    ├── next.config.js
    │
    ├── app/
    │   ├── layout.js                  ← Root layout, auth context provider
    │   ├── page.js                    ← Landing / redirect to feed
    │   │
    │   ├── (auth)/
    │   │   ├── login/page.js          ← Login form + 2FA step
    │   │   └── register/page.js       ← Registration form
    │   │
    │   ├── feed/
    │   │   └── page.js                ← Public feed of posts
    │   │
    │   ├── posts/
    │   │   ├── new/page.js            ← Create post form
    │   │   └── [id]/page.js           ← Single post + comments
    │   │
    │   ├── profile/
    │   │   └── [username]/page.js     ← Public profile page
    │   │
    │   └── messages/
    │       ├── page.js                ← Conversation list
    │       └── [conversationId]/page.js ← Real-time chat UI
    │
    ├── components/
    │   ├── auth/                      ← LoginForm, RegisterForm, TwoFactorInput
    │   ├── feed/                      ← PostCard, FeedList, PostFilter
    │   ├── posts/                     ← PostEditor, PostDetail, CommentThread
    │   ├── messages/                  ← ConversationList, ChatWindow, MessageBubble
    │   ├── profile/                   ← ProfileHeader, ProfileEditor, ProfileStats
    │   └── shared/                    ← Navbar, Avatar, Button, Modal, Spinner
    │
    ├── lib/
    │   ├── api.js                     ← Axios/fetch wrapper with JWT injection
    │   ├── socket.js                  ← Socket.IO client singleton
    │   └── crypto/
    │       ├── rsa.js                 ← Client-side RSA (mirrors backend/crypto/rsa.js)
    │       └── ecc.js                 ← Client-side ECC (mirrors backend/crypto/ecc.js)
    │
    ├── context/
    │   └── AuthContext.js             ← Global auth state, user keys in memory
    │
    └── hooks/
        ├── useAuth.js                 ← Login/logout/register actions
        ├── useMessages.js             ← Socket.IO subscription + message state
        └── useDecrypt.js              ← Decrypt field(s) using in-memory private key
```

---

## 4. Security Architecture

### The Four Pillars

```
┌─────────────────────────────────────────────────────────────────┐
│  1. ASYMMETRIC ENCRYPTION                                        │
│     RSA-OAEP  →  posts, comments, messages, 2FA secrets         │
│     ECC/ECIES →  user registration data, profile fields         │
├─────────────────────────────────────────────────────────────────┤
│  2. PASSWORD SECURITY                                            │
│     Custom hash + salt (PBKDF2-like, no bcrypt npm)             │
│     Salt: 32 random bytes generated at registration             │
│     Iterations: 100,000 rounds of SHA-256 chaining              │
├─────────────────────────────────────────────────────────────────┤
│  3. INTEGRITY (MAC)                                              │
│     HMAC-SHA256 over every encrypted document's fields          │
│     Verified on every read — tampered docs are rejected         │
├─────────────────────────────────────────────────────────────────┤
│  4. SESSION SECURITY                                             │
│     JWT (15 min expiry) stored in httpOnly cookie               │
│     Refresh token (7 days) stored in httpOnly cookie            │
│     tokenVersion field invalidates all tokens on password change│
└─────────────────────────────────────────────────────────────────┘
```

### What Is Never Stored in Plaintext

| Data | What's stored instead |
|------|-----------------------|
| Username | ECC ciphertext + SHA-256 hash (for lookups) |
| Email | ECC ciphertext + SHA-256 hash (for login lookup) |
| Contact info | ECC ciphertext |
| Password | custom-hash(password + salt) |
| 2FA secret | RSA-OAEP ciphertext |
| Post content | RSA-OAEP ciphertext (chunked) |
| Comment content | RSA-OAEP ciphertext (chunked) |
| Message content | RSA-OAEP ciphertext (double-encrypted) |
| Profile bio/location | ECC ciphertext |
| Private keys | RSA-encrypted with server master key |

---

## 5. Encryption Strategy — The 6 Features

These are the six distinct features that use encryption, satisfying the requirement for asymmetric encryption across multiple operations using two different algorithms.

### Feature 1 — User Registration Data (ECC/ECIES)
- **Fields:** `encryptedUsername`, `encryptedEmail`, `encryptedContact`
- **Algorithm:** ECC using secp256k1 curve, ECIES mode
- **Key used:** Server ECC public key (for deterministic encryption allowing unique index checks)
- **Why ECC here:** ECC keys are shorter and faster for bulk field encryption; fits profile/identity data well
- **MAC:** `hmacSignature` = HMAC(encryptedUsername + encryptedEmail + encryptedContact)

### Feature 2 — Two-Factor Authentication Secret (RSA-OAEP)
- **Fields:** `encryptedTwoFactorSecret`
- **Algorithm:** RSA-OAEP, 2048-bit key
- **Key used:** Server RSA master public key
- **Flow:** TOTP secret generated → RSA-encrypted → stored. On 2FA verify: server decrypts secret → validates TOTP token
- **MAC:** Covered by User document `hmacSignature`

### Feature 3 — Post Content (RSA-OAEP)
- **Fields:** `encryptedTitle`, `encryptedContent`, `encryptedChunks[]`
- **Algorithm:** RSA-OAEP, 2048-bit
- **Key used:** Server RSA public key (server decrypts for all authorized readers)
- **Chunking:** RSA 2048 can encrypt max ~190 bytes. Content is split into 150-byte chunks, each chunk encrypted individually, stored in `encryptedChunks[]`
- **MAC:** `hmacSignature` = HMAC(encryptedTitle + encryptedContent + authorId + createdAt)

### Feature 4 — Comments (RSA-OAEP)
- **Fields:** `encryptedContent`, `encryptedChunks[]`
- **Algorithm:** RSA-OAEP, 2048-bit
- **Key used:** Server RSA public key
- **MAC:** `hmacSignature` = HMAC(encryptedContent + authorId + postId + createdAt)

### Feature 5 — Direct Messages (RSA-OAEP, double-encrypted)
- **Fields:** `encryptedForSender`, `encryptedForRecipient`, `chunksForSender[]`, `chunksForRecipient[]`
- **Algorithm:** RSA-OAEP
- **Key used:** Each party's own RSA public key — message encrypted twice, once per participant
- **Why double-encrypt:** No shared symmetric key; both parties can independently decrypt their copy without sharing private keys
- **MAC:** `hmacSignature` = HMAC(encryptedForRecipient + senderId + conversationId + timestamp)

### Feature 6 — Profile Fields (ECC/ECIES)
- **Fields:** `encryptedBio`, `encryptedLocation`, `encryptedWebsite`, `encryptedOccupation`
- **Algorithm:** ECC/ECIES, secp256k1
- **Key used:** Server ECC public key
- **MAC:** `hmacSignature` = HMAC(encryptedBio + encryptedLocation + encryptedWebsite + userId)

---

## 6. Crypto Engine — From Scratch Rules

> The project requirement explicitly bans built-in encryption from frameworks.
> No `crypto.subtle`, no `crypto` Node module for encryption, no `bcrypt`, no `jsonwebtoken` for signing (implement manually), no `elliptic` npm package.

### `backend/crypto/rsa.js` — What it must implement

```
RSA Key Generation:
  - Generate two large primes p and q (Miller-Rabin primality test)
  - n = p * q
  - φ(n) = (p-1)(q-1)
  - e = 65537 (standard public exponent)
  - d = modular inverse of e mod φ(n) (extended Euclidean algorithm)
  - Public key: (n, e) | Private key: (n, d)

RSA-OAEP Encrypt(message, publicKey):
  - OAEP padding: hash-based padding using custom SHA-256
  - Modular exponentiation: BigInt pow(message, e, n)
  - Return base64 ciphertext

RSA-OAEP Decrypt(ciphertext, privateKey):
  - Modular exponentiation: BigInt pow(ciphertext, d, n)
  - Remove OAEP padding
  - Return plaintext

Chunk helpers:
  - chunkEncrypt(longString, publicKey) → string[]
  - chunkDecrypt(chunks[], privateKey) → string
```

### `backend/crypto/ecc.js` — What it must implement

```
Curve: secp256k1
  - p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn
  - a  = 0n
  - b  = 7n
  - Gx, Gy = secp256k1 generator point (hardcoded BigInt constants)
  - n  = curve order (hardcoded)

Point arithmetic (all BigInt):
  - pointAdd(P, Q)          → R
  - pointDouble(P)          → R
  - scalarMult(k, P)        → R  (double-and-add algorithm)
  - modInverse(a, m)        → BigInt (extended Euclidean)

Key Generation:
  - privateKey = random BigInt in [1, n-1]
  - publicKey  = scalarMult(privateKey, G)

ECIES Encrypt(message, recipientPublicKey):
  - Generate ephemeral key pair (r, R)
  - sharedPoint = scalarMult(r, recipientPublicKey)
  - Use sharedPoint.x as XOR key stream seed (no AES — forbidden)
  - XOR each byte of message with hash(sharedPoint.x + index)
  - Output: { R (ephemeral public key), ciphertext, mac }

ECIES Decrypt(ciphertext, recipientPrivateKey):
  - sharedPoint = scalarMult(recipientPrivateKey, R)
  - Reconstruct XOR key stream from sharedPoint.x
  - XOR to recover plaintext
  - Verify mac
```

### `backend/crypto/hmac.js` — What it must implement

```
SHA-256 from scratch:
  - 64 round constants (hardcoded)
  - Message padding, schedule, compression function
  - All operations as 32-bit unsigned integer arithmetic

HMAC-SHA256(key, message):
  - ipad = key XOR 0x36 (repeated)
  - opad = key XOR 0x5c (repeated)
  - HMAC = SHA256(opad + SHA256(ipad + message))
  - Return hex string

sign(fields[], serverHmacKey) → hmacSignature string
verify(fields[], serverHmacKey, storedSignature) → boolean
```

### `backend/crypto/hash.js` — What it must implement

```
generateSalt():
  - 32 cryptographically random bytes via Math.random seeded with
    performance.now() + process.hrtime() (or use crypto.getRandomValues
    which is allowed — it's not encryption, it's entropy)
  - Return hex string

hashPassword(password, salt):
  - Concatenate password + salt
  - Apply SHA-256 (from hmac.js) 100,000 times iteratively
  - Return final hex digest

verifyPassword(inputPassword, salt, storedHash):
  - hashPassword(inputPassword, salt) === storedHash
```

### `backend/crypto/utils.js` — Helpers

```
- toBase64(buffer) / fromBase64(string)
- toHex(buffer) / fromHex(string)
- bigIntToBytes(n, length) / bytesToBigInt(bytes)
- randomBigInt(min, max)    ← uses crypto.getRandomValues (allowed)
- sha256(message)           ← delegates to hmac.js
- stringToBytes / bytesToString
```

---

## 7. Data Flow — Every Major Operation

### Registration Flow

```
Client                          Server                         Database
  │                               │                               │
  ├─ POST /auth/register          │                               │
  │  { username, email,           │                               │
  │    password, contact }        │                               │
  │                               │                               │
  │                        generateSalt()                         │
  │                        hashPassword(pw, salt)                 │
  │                               │                               │
  │                        ECC.generateKeyPair()  → (eccPub, eccPriv)
  │                        RSA.generateKeyPair()  → (rsaPub, rsaPriv)
  │                               │                               │
  │                        ECC.encrypt(username, serverEccPub)    │
  │                        ECC.encrypt(email, serverEccPub)       │
  │                        ECC.encrypt(contact, serverEccPub)     │
  │                               │                               │
  │                        SHA256(username) → usernameHash        │
  │                        SHA256(email)    → emailHash           │
  │                               │                               │
  │                        RSA.encrypt(totpSecret, serverRsaPub)  │
  │                        RSA.encrypt(rsaPriv, serverRsaPub)     │
  │                        ECC.encrypt(eccPriv, serverRsaPub)     │
  │                               │                               │
  │                        HMAC.sign([encUser, encEmail, encContact])
  │                               │                               │
  │                               ├── User.create({...}) ────────►│
  │                               ├── Profile.create({...}) ─────►│
  │                               ├── KeyStore.create(RSA) ──────►│
  │                               ├── KeyStore.create(ECC) ──────►│
  │                               │                               │
  │◄─ 201 { message: "ok" } ──────│                               │
```

### Login Flow

```
Client                          Server                         Database
  │                               │                               │
  ├─ POST /auth/login             │                               │
  │  { email, password }          │                               │
  │                               │                               │
  │                        SHA256(email) → emailHash              │
  │                               ├── User.findOne({emailHash}) ─►│
  │                               │◄─ userDoc ────────────────────│
  │                               │                               │
  │                        HMAC.verify(userDoc fields)  ← tamper check
  │                        hashPassword(password, userDoc.salt)   │
  │                        compare → match?                       │
  │                               │                               │
  │                        if 2FA enabled:                        │
  │◄─ 200 { requires2FA: true } ──│                               │
  │                               │                               │
  ├─ POST /auth/2fa/verify        │                               │
  │  { totpCode }                 │                               │
  │                               │                               │
  │                        RSA.decrypt(encTotpSecret, serverPriv) │
  │                        TOTP.verify(totpCode, secret)          │
  │                               │                               │
  │                        JWT.sign({ userId, role }, secret, 15m)│
  │                        refreshToken = randomBytes → SHA256 → store
  │                               │                               │
  │◄─ 200 { accessToken }         │                               │
  │   Set-Cookie: refreshToken (httpOnly, secure, sameSite=strict)│
```

### Create Post Flow

```
Client                          Server                         Database
  │                               │                               │
  ├─ POST /posts                  │                               │
  │  { title, content,            │                               │
  │    category, tags }           │                               │
  │  Authorization: Bearer <JWT>  │                               │
  │                               │                               │
  │                        authenticate middleware                 │
  │                        JWT.verify() → req.user                │
  │                               │                               │
  │                        RSA.chunkEncrypt(title, serverRsaPub)  │
  │                        RSA.chunkEncrypt(content, serverRsaPub)│
  │                               │                               │
  │                        HMAC.sign([encTitle, encContent,       │
  │                                   authorId, timestamp])       │
  │                               │                               │
  │                               ├── Post.create({...}) ────────►│
  │                               │                               │
  │◄─ 201 { postId } ─────────────│                               │
```

### Read Feed Flow

```
Client                          Server                         Database
  │                               │                               │
  ├─ GET /posts?page=1            │                               │
  │                               ├── Post.find({isDeleted:false})►│
  │                               │◄─ encryptedPostDocs ──────────│
  │                               │                               │
  │                        for each post:                         │
  │                          HMAC.verify() ← reject if tampered   │
  │                          RSA.chunkDecrypt(encTitle, serverPriv)│
  │                          RSA.chunkDecrypt(encContent, serverPriv)
  │                               │                               │
  │◄─ 200 [{ id, title,           │                               │
  │          content, author,     │                               │
  │          category, ... }]     │                               │
```

### Send Message Flow

```
Client                          Server                         Database
  │                               │                               │
  ├─ Socket.IO emit               │                               │
  │  'send_message'               │                               │
  │  { recipientId, content }     │                               │
  │                               │                               │
  │                        authenticate socket (JWT from cookie)  │
  │                               │                               │
  │                        fetch sender RSA pubKey from KeyStore  │
  │                        fetch recipient RSA pubKey from KeyStore│
  │                               │                               │
  │                        RSA.chunkEncrypt(content, senderPub)   │
  │                          → encryptedForSender                 │
  │                        RSA.chunkEncrypt(content, recipientPub)│
  │                          → encryptedForRecipient              │
  │                               │                               │
  │                        HMAC.sign([encForRecipient,            │
  │                                   senderId, convId, ts])      │
  │                               │                               │
  │                               ├── Message.create({...}) ─────►│
  │                               ├── Conversation.updateOne() ──►│
  │                               │                               │
  │                        Socket.IO emit to recipient room:      │
  │                          'new_message' { encryptedForRecipient}│
  │◄─ Socket.IO emit to sender:   │                               │
  │   'message_sent' { id, ts }   │                               │
```

---

## 8. Database Models

### User.js
**Purpose:** Core auth document. Stores identity (ECC-encrypted), credentials (hashed), key pairs, and session control.

**Critical fields:**
- `encryptedUsername/Email/Contact` — ECC ciphertext
- `usernameHash / emailHash` — SHA-256 for lookups (never decrypt to search)
- `passwordHash + passwordSalt` — custom PBKDF2-like
- `encryptedTwoFactorSecret` — RSA-OAEP
- `publicKey / eccPublicKey` — plaintext (public by design)
- `encryptedPrivateKey / encryptedEccPrivateKey` — double-encrypted
- `keyVersion` — must match KeyStore version; increment on rotation
- `tokenVersion` — increment to invalidate all JWTs instantly
- `hmacSignature` — HMAC over all encrypted identity fields
- `role` — "user" | "admin" (RBAC)

### Post.js
**Purpose:** Stores user-posted needs/requests. All text content RSA-encrypted.

**Critical fields:**
- `encryptedTitle / encryptedContent` — RSA-OAEP
- `encryptedChunks[]` — overflow chunks for long content
- `category` — plaintext (for feed filtering without decryption)
- `tags[]` — plaintext (for discovery)
- `keyVersion` — used for re-encryption jobs after key rotation
- `hmacSignature` — HMAC over encrypted fields + author + timestamp
- `isDeleted / deletedBy` — soft delete (admin can delete any post)

### Comment.js
**Purpose:** Threaded comments on posts. One level of replies via `parentComment`.

**Critical fields:**
- `encryptedContent / encryptedChunks[]` — RSA-OAEP
- `parentComment` — null = top-level, ObjectId = reply
- `keyVersion + hmacSignature` — same pattern as Post

### Message.js (two schemas in one file)

**Conversation schema purpose:** Tracks the thread between two users. Holds unread counts and last message preview.

**Message schema purpose:** Individual encrypted messages. Double-encrypted — once per participant.

**Critical fields (Message):**
- `encryptedForSender / chunksForSender[]` — RSA with sender's public key
- `encryptedForRecipient / chunksForRecipient[]` — RSA with recipient's public key
- `senderKeyVersion / recipientKeyVersion` — for re-encryption after key rotation
- `hmacSignature` — HMAC over encryptedForRecipient + senderId + convId + ts
- `status` — "sent" | "delivered" | "read"

### Profile.js
**Purpose:** Extended public profile. Separated from User to avoid loading auth fields on profile page requests.

**Critical fields:**
- `encryptedBio / encryptedLocation / encryptedWebsite / encryptedOccupation` — ECC/ECIES
- `displayName / avatarUrl / bannerUrl` — plaintext (user chose to make public)
- `privacy` — controls which fields are visible to others
- `postCount / followerCount / followingCount` — denormalised for fast render
- `hmacSignature` — HMAC over encrypted fields + userId

### KeyStore.js
**Purpose:** Satisfies the Key Management Module requirement. One document per key version per algorithm per user.

**Critical fields:**
- `algorithm` — "RSA" | "ECC"
- `version` — increments on rotation
- `publicKey` — plaintext
- `encryptedPrivateKey` — RSA-encrypted with server master key
- `status` — "active" | "rotating" | "archived" | "revoked"
- `expiresAt` — set to +90 days; cron job queries this to trigger rotation
- `hmacSignature` — HMAC over all key material fields

---

## 9. Backend — File-by-File Responsibilities

### `server.js`
- Create Express app
- Attach Socket.IO to HTTP server
- Mount all routes under `/api`
- Start listening on `process.env.PORT`
- Connect to MongoDB via `config/db.js`

### `app.js`
- `express.json()` body parser
- CORS configuration (allow Next.js origin, credentials: true)
- Cookie parser
- Mount `rateLimiter` globally
- Mount all route files

### `config/db.js`
- `mongoose.connect(process.env.MONGO_URI)`
- Log connection success/failure
- Export connect function

### `config/env.js`
- Import all env vars
- Throw startup error if any required var is missing
- Export typed env object used everywhere else

### `services/authService.js`
- `register(userData)` — runs full registration flow (encrypt → hash → save → generate keys)
- `login(email, password)` — lookup by emailHash, verify password, return 2FA flag or tokens
- `verify2FA(userId, totpCode)` — decrypt TOTP secret, verify code, issue JWT
- `refreshTokens(refreshToken)` — validate, issue new access token
- `logout(userId)` — clear refreshTokenHash

### `services/keyManager.js`
- `generateUserKeys(userId)` — creates RSA + ECC key pairs, saves to KeyStore, updates User
- `rotateKeys(userId)` — archives old KeyStore, generates new pair, updates keyVersion
- `getPublicKey(userId, algorithm)` — fetch active public key for a user
- `scheduleRotationCheck()` — cron-style function checking KeyStore.expiresAt

### `middleware/authenticate.js`
- Extract JWT from `Authorization` header or cookie
- Verify signature (custom JWT verify from scratch)
- Check `tokenVersion` matches User document
- Attach `req.user = { id, role, keyVersion }`

### `middleware/authorize.js`
- `authorize(...roles)` — factory that returns middleware
- Usage: `router.delete('/:id', authenticate, authorize('admin'), handler)`
- Returns 403 if `req.user.role` not in allowed roles

### `middleware/verifyMac.js`
- Called after fetching any document from DB
- `HMAC.verify(doc.fields, serverKey, doc.hmacSignature)`
- Throws 500 with "Data integrity check failed" if MAC is invalid
- Never serve a document that fails MAC verification

### `sockets/messageSocket.js`
- `io.on('connection', socket => ...)`
- Authenticate socket via JWT in handshake cookie
- `socket.join(userId)` — personal room for delivery
- Handle `send_message` event → call messageService → emit to recipient room
- Handle `mark_read` event → update message status

---

## 10. Frontend — File-by-File Responsibilities

### `context/AuthContext.js`
- Stores `{ user, accessToken, privateKey, eccPrivateKey }` in React state (never localStorage)
- Private keys live in memory only — cleared on logout or page refresh
- On refresh: re-authenticate via refresh token cookie → re-derive or re-fetch private keys
- Provides `login()`, `logout()`, `register()` actions to the whole app

### `lib/api.js`
- Axios instance with `baseURL = process.env.NEXT_PUBLIC_API_URL`
- Request interceptor: attach `Authorization: Bearer <accessToken>` from AuthContext
- Response interceptor: on 401, attempt token refresh then retry
- `withCredentials: true` for cookie handling

### `lib/socket.js`
- Creates a single Socket.IO client instance
- Connects with `{ withCredentials: true }` so auth cookie is sent
- Exports `socket` singleton — import this everywhere, don't create new instances

### `lib/crypto/rsa.js` and `lib/crypto/ecc.js`
- Mirror of backend crypto files — same algorithms, same BigInt logic
- Used for: verifying encrypted data client-side, future client-side encryption option
- Keep in sync with backend crypto files manually

### `hooks/useDecrypt.js`
- Takes an array of encrypted fields + the current user's private key from AuthContext
- Calls RSA.chunkDecrypt or ECC.decrypt as appropriate
- Memoises results so decryption doesn't re-run on every render

### `hooks/useMessages.js`
- Subscribes to `new_message` socket event
- Adds incoming message to local state
- Triggers notification badge update

---

## 11. RBAC — Role-Based Access Control

Two roles: `user` and `admin`. Role stored in JWT payload and in `User.role`.

| Action                    | user | admin |
|---------------------------|------|-------|
| Create post               |  ✅  |  ✅  |
| Edit own post             |  ✅  |  ✅  |
| Delete own post           |  ✅  |  ✅  |
| Delete any post           |  ❌  |  ✅  |
| Edit own profile          |  ✅  |  ✅  |
| View any profile          |  ✅  |  ✅  |
| Send DMs                  |  ✅  |  ✅  |
| Delete any user           |  ❌  |  ✅  |
| Rotate any user's keys    |  ❌  |  ✅  |
| View all KeyStore entries |  ❌  |  ✅  |

Implementation pattern in routes:
```js
// Any authenticated user
router.get('/posts', authenticate, postController.getFeed);

// Only the post owner
router.patch('/posts/:id', authenticate, postController.update);
// (ownership check happens inside postController.update)

// Admin only
router.delete('/admin/users/:id', authenticate, authorize('admin'), adminController.deleteUser);
```

---

## 12. Session & Token Management

### Access Token (JWT)
- Expiry: 15 minutes
- Payload: `{ userId, role, keyVersion, tokenVersion, iat, exp }`
- Stored: `Authorization` header (set by frontend on every request)
- Signing: Custom HMAC-SHA256 implementation — no `jsonwebtoken` npm

### Refresh Token
- Expiry: 7 days
- Format: 32 random bytes → hex string
- Storage: httpOnly, Secure, SameSite=Strict cookie
- Server stores: SHA-256(refreshToken) in `User.refreshTokenHash`
- On use: verify hash match → issue new access token → rotate refresh token

### Token Invalidation
- `User.tokenVersion` — increment this to instantly invalidate all JWTs
- Triggered by: password change, logout-all-devices, admin ban
- JWT middleware checks `payload.tokenVersion === user.tokenVersion`

### Session Hijacking Prevention
- httpOnly cookies — JS cannot read refresh token
- SameSite=Strict — CSRF requests don't send cookies
- Short access token lifetime — 15 min exposure window
- tokenVersion rotation — instant global invalidation

---

## 13. Key Management Module

### Key Generation
- On registration: generate RSA-2048 key pair + secp256k1 ECC key pair
- Store in KeyStore with `status: "active"`, `version: 1`
- `expiresAt` = `createdAt + 90 days`

### Key Distribution
- Public keys: freely available via `GET /keys/public/:userId`
- Private keys: never sent over the wire — only decrypted server-side when needed
- Before sending messages: server fetches recipient's public key from KeyStore

### Key Rotation
- Triggered by: cron job (daily check of `expiresAt`), manual admin trigger, or user request
- Flow:
  1. Generate new key pair
  2. Create new KeyStore document (`status: "active"`, `version: n+1`)
  3. Archive old KeyStore (`status: "archived"`, `rotatedToVersion: n+1`)
  4. Update `User.keyVersion`, `User.publicKey`, `User.encryptedPrivateKey`
  5. Queue re-encryption job for all posts/messages using old `keyVersion`

### Key Revocation
- Admin can revoke a key: set KeyStore `status: "revoked"`, `revokedAt: now`
- All content encrypted with revoked key becomes inaccessible (intentional for security)

---

## 14. Real-Time Messaging

### Architecture
```
Client A (sender)
    │
    ├── socket.emit('send_message', { recipientId, content })
    │
Server (messageSocket.js)
    ├── authenticate socket handshake
    ├── fetch A's public key from KeyStore
    ├── fetch B's public key from KeyStore
    ├── RSA.chunkEncrypt(content, A.publicKey) → encryptedForSender
    ├── RSA.chunkEncrypt(content, B.publicKey) → encryptedForRecipient
    ├── HMAC.sign([encryptedForRecipient, senderId, convId, ts])
    ├── Message.create({...})
    ├── Conversation.updateOne({ lastMessageAt, preview })
    └── io.to(recipientId).emit('new_message', { encryptedForRecipient })

Client B (recipient)
    └── socket.on('new_message', msg => {
          // server decrypts using B's key when B fetches message history
          // or: client decrypts if private key is in memory
        })
```

### Socket Rooms
- Each user joins their own room named by their userId on connection
- `io.to(userId).emit(...)` delivers to all that user's active sessions

### Message History
- `GET /messages/:conversationId` — server fetches messages, decrypts `encryptedForRecipient` (using server's access to recipient's key), returns plaintext
- Pagination: cursor-based on `createdAt`

---

## 15. Environment Variables

```env
# backend/.env

# Server
PORT=5000
NODE_ENV=development

# MongoDB
MONGO_URI=mongodb+srv://...

# JWT
JWT_SECRET=<32+ random bytes hex>
JWT_REFRESH_SECRET=<32+ random bytes hex>

# HMAC
HMAC_SERVER_KEY=<32+ random bytes hex>

# Master RSA key (used to encrypt all user private keys)
# Generated once, stored securely — never rotate without re-encrypting all keys
SERVER_RSA_PUBLIC_KEY=<base64 PEM>
SERVER_RSA_PRIVATE_KEY=<base64 PEM>

# Master ECC key (used to encrypt user/profile data)
SERVER_ECC_PUBLIC_KEY=<base64 compressed point>
SERVER_ECC_PRIVATE_KEY=<base64 scalar>

# UploadThing
UPLOADTHING_SECRET=...
UPLOADTHING_APP_ID=...

# Frontend origin for CORS
CLIENT_ORIGIN=http://localhost:3000
```

```env
# frontend/.env.local
NEXT_PUBLIC_API_URL=http://localhost:5000/api
NEXT_PUBLIC_SOCKET_URL=http://localhost:5000
```

---

## 16. Important Rules & Constraints

### Crypto Rules (non-negotiable)
1. **No built-in encryption.** `crypto.subtle`, `crypto.createCipher`, `bcrypt`, `elliptic`, `node-forge` — all banned. Implement from scratch using `BigInt`.
2. **No symmetric encryption.** No AES, no ChaCha20, no XSalsa. Everything asymmetric (RSA or ECC) or hashed (HMAC/SHA-256).
3. **Two algorithms must be used.** RSA handles posts, comments, messages, 2FA. ECC handles user registration, profile. Never use only one.
4. **Every encrypted document needs a MAC.** Compute and store `hmacSignature` on write. Verify on every read. Reject documents that fail.
5. **`crypto.getRandomValues`** is allowed — it is an entropy source, not an encryption function.

### Code Rules
6. **ESM everywhere.** `import/export` syntax. No `require()`. Node 18+.
7. **`.js` extensions required** in all local imports (ESM Node requirement).
8. **Never log plaintext sensitive data.** No `console.log(password)`, no logging decrypted content.
9. **Never return encrypted blobs to the client.** Always decrypt server-side before responding (except the user's own private key operations).
10. **keyVersion must always travel with encrypted content.** Posts, messages, comments all store `keyVersion` so re-encryption after rotation is possible.

### Database Rules
11. **Never store plaintext usernames, emails, passwords, or message content** — see the "What Is Never Stored in Plaintext" table in Section 4.
12. **Hash-before-query pattern for lookups.** Always `SHA256(email)` before querying `emailHash`. Never decrypt all rows to find one.
13. **Soft-delete only for posts and comments.** Set `isDeleted: true`. Hard deletes only via scheduled admin jobs.
14. **AuditLog is removed from this project.** Do not re-add it unless explicitly requested.
15. **Notification model is removed from this project.** Do not re-add it unless explicitly requested.
