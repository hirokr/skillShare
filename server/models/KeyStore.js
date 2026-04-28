import mongoose from "mongoose";
/**
 * KEY STORE MODEL
 *
 * Satisfies the "Key Management Module" requirement:
 * generation, distribution, storage, and rotation.
 *
 * Every time a user's keys are rotated, a new KeyStore document is created
 * and the old one is archived (not deleted — old encrypted content still
 * references old keys for re-encryption jobs).
 *
 * Encryption strategy:
 *  - encryptedPrivateKey → the private key blob is RSA-encrypted with a
 *    server master key before storage (double-encrypted)
 *  - hmacSignature → HMAC over the stored key material to detect tampering
 */
const KeyStoreSchema = new mongoose.Schema(
	{
		// ── Owner ──────────────────────────────────────────────────────────────────
		user: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
			index: true,
		},

		// ── Key type ───────────────────────────────────────────────────────────────
		algorithm: {
			type: String,
			enum: ["RSA", "ECC"],
			required: true,
		},
		version: {
			type: Number,
			required: true,
			// Monotonically increasing per user per algorithm
		},

		// ── Key material ───────────────────────────────────────────────────────────
		publicKey: {
			type: String,
			required: true,
			// Plaintext public key (PEM / compressed point for ECC)
		},
		encryptedPrivateKey: {
			type: String,
			required: true,
			// Private key encrypted with server master key + user-derived key
			// Algorithm: RSA-OAEP(server_master_pub, privateKeyBytes)
		},

		// ── Encryption parameters ──────────────────────────────────────────────────
		keySize: {
			type: Number,
			// RSA: 2048 or 4096. ECC: 256 (secp256k1 bit length)
		},
		curve: {
			type: String,
			default: null,
			// ECC only: "secp256k1"
		},

		// ── Lifecycle ──────────────────────────────────────────────────────────────
		status: {
			type: String,
			enum: ["active", "rotating", "archived", "revoked"],
			default: "active",
		},
		activatedAt: {
			type: Date,
			default: Date.now,
		},
		expiresAt: {
			type: Date,
			default: null,
			// Set a 90-day rotation policy in the key manager service
		},
		revokedAt: {
			type: Date,
			default: null,
		},
		rotatedToVersion: {
			type: Number,
			default: null,
			// Points to the new version after rotation
		},

		// ── Distribution log ───────────────────────────────────────────────────────
		distributedTo: [
			{
				// Track which services/sessions received this public key
				service: { type: String },
				distributedAt: { type: Date, default: Date.now },
			},
		],

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
			// HMAC over (publicKey + encryptedPrivateKey + user + version + algorithm)
		},
	},
	{
		timestamps: true,
	},
);

KeyStoreSchema.index({ user: 1, algorithm: 1, version: -1 });
KeyStoreSchema.index({ user: 1, status: 1 });
KeyStoreSchema.index({ expiresAt: 1 }); // For rotation cron job queries

export default mongoose.model("KeyStore", KeyStoreSchema);
