import mongoose from "mongoose";
/**
 * USER MODEL
 *
 * Encryption strategy:
 *  - encryptedUsername, encryptedEmail, encryptedContact → ECC/ECIES encrypted
 *  - passwordHash  → custom hash+salt (no plaintext ever stored)
 *  - twoFactorSecret → RSA encrypted before storage
 *  - publicKey     → stored plaintext (public by design)
 *  - encryptedPrivateKey → RSA-encrypted private key blob
 *
 * MAC fields (hmacSignature) verify that encrypted blobs haven't been tampered with.
 */
const UserSchema = new mongoose.Schema(
	{
		// ── Identity (all ECC-encrypted) ──────────────────────────────────────────
		encryptedUsername: {
			type: String,
			required: true,
			// ECC-encrypted ciphertext (base64)
		},
		encryptedEmail: {
			type: String,
			required: true,
			unique: true,
			// ECC-encrypted; unique index on ciphertext — use a deterministic ECC
			// variant (ECIES with fixed IV derived from email hash) so queries work
		},
		encryptedContact: {
			type: String,
			default: null,
			// Phone / secondary contact — ECC-encrypted
		},

		// ── Search handle (hashed, not encrypted, for lookups) ────────────────────
		usernameHash: {
			type: String,
			required: true,
			unique: true,
			// SHA-256(username) — allows username-uniqueness check & @mention lookups
			// without decrypting every row
		},
		emailHash: {
			type: String,
			required: true,
			unique: true,
			// SHA-256(email) — login lookup key
		},

		// ── Authentication ─────────────────────────────────────────────────────────
		passwordHash: {
			type: String,
			required: true,
			// Custom hash: PBKDF2-like with manual salt (no bcrypt npm)
		},
		passwordSalt: {
			type: String,
			required: true,
			// Random 32-byte hex salt generated at registration
		},

		// ── Two-factor authentication ──────────────────────────────────────────────
		twoFactorEnabled: {
			type: Boolean,
			default: false,
		},
		encryptedTwoFactorSecret: {
			type: String,
			default: null,
			// TOTP secret encrypted with RSA-OAEP before storage
		},

		// ── Key pairs ──────────────────────────────────────────────────────────────
		publicKey: {
			type: String,
			required: true,
			// RSA public key (PEM-like base64) — shared openly
		},
		encryptedPrivateKey: {
			type: String,
			required: true,
			// User's RSA private key encrypted with their password-derived ECC key
		},
		eccPublicKey: {
			type: String,
			required: true,
			// ECC public key (secp256k1 point, compressed, base64)
		},
		encryptedEccPrivateKey: {
			type: String,
			required: true,
			// ECC private key scalar encrypted with RSA
		},

		// ── Key rotation ───────────────────────────────────────────────────────────
		keyVersion: {
			type: Number,
			default: 1,
			// Increments on each key rotation; old messages reference old key version
		},
		keyRotatedAt: {
			type: Date,
			default: null,
		},

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
			// HMAC-SHA256 over (encryptedUsername + encryptedEmail + encryptedContact)
			// Verified on every read to detect tampering
		},

		// ── Profile ────────────────────────────────────────────────────────────────
		profilePictureUrl: {
			type: String,
			default: null,
			// UploadThing URL — not sensitive, stored in plaintext
		},
		role: {
			type: String,
			enum: ["user", "admin"],
			default: "user",
			// RBAC: admins can delete any post/user
		},

		// ── Social graph ───────────────────────────────────────────────────────────
		followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
		following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

		// ── Session security ───────────────────────────────────────────────────────
		refreshTokenHash: {
			type: String,
			default: null,
			// SHA-256 of the active refresh token; invalidated on logout
		},
		tokenVersion: {
			type: Number,
			default: 0,
			// Increment to invalidate all existing JWTs for this user
		},
		lastLoginAt: {
			type: Date,
			default: null,
		},
		isActive: {
			type: Boolean,
			default: true,
			// Soft-delete / ban flag
		},
	},
	{
		timestamps: true, // createdAt, updatedAt
	},
);

// ── Indexes ────────────────────────────────────────────────────────────────────
UserSchema.index({ emailHash: 1 });
UserSchema.index({ usernameHash: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ followers: 1 });

export default mongoose.model("User", UserSchema);