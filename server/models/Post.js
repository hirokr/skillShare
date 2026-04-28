import mongoose from "mongoose";
/**
 * POST MODEL
 *
 * Posts are the core of the social space — users share needs/requests.
 *
 * Encryption strategy:
 *  - encryptedContent → RSA-OAEP encrypted post body
 *  - encryptedTitle   → RSA-OAEP encrypted title
 *  - mediaUrls        → plaintext UploadThing URLs (not sensitive)
 *  - hmacSignature    → HMAC-SHA256 over encrypted fields for tamper detection
 *
 * The author's RSA public key is used to encrypt so only they (and admins
 * with server-side master key access) can fully decrypt the content.
 * Other users see content decrypted server-side after authorization check.
 */
const PostSchema = new mongoose.Schema(
	{
		// ── Author ─────────────────────────────────────────────────────────────────
		author: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
			index: true,
		},

		// ── Encrypted content (RSA-OAEP) ──────────────────────────────────────────
		encryptedTitle: {
			type: String,
			required: true,
			// RSA-OAEP ciphertext, base64-encoded
		},
		encryptedContent: {
			type: String,
			required: true,
			// RSA-OAEP ciphertext of the post body
		},

		// ── Encrypted session key (hybrid RSA envelope) ────────────────────────────
		// RSA can only encrypt small payloads. For longer posts we use a
		// randomly generated AES-equivalent key, encrypt the content with it
		// (XOR stream cipher counts as "symmetric" which is banned), so instead
		// we chunk the content and encrypt each chunk with RSA individually.
		// OR: we store it as one RSA ciphertext per paragraph chunk.
		// encryptedChunks stores the array if content exceeds RSA block size.
		encryptedChunks: {
			type: [String],
			default: [],
			// Array of RSA-encrypted chunks when content > RSA block size
		},

		// ── Media ──────────────────────────────────────────────────────────────────
		mediaUrls: {
			type: [String],
			default: [],
			// UploadThing CDN URLs — images/files attached to the post
		},

		// ── Post metadata ──────────────────────────────────────────────────────────
		category: {
			type: String,
			enum: ["need", "offer", "question", "event", "other"],
			default: "need",
			// Unencrypted so feed can be filtered without decrypting everything
		},
		tags: {
			type: [String],
			default: [],
			// Plaintext tags for discovery (e.g. ["food", "urgent"])
		},
		isAnonymous: {
			type: Boolean,
			default: false,
			// If true, author ObjectId is hidden from API responses (but stored)
		},
		status: {
			type: String,
			enum: ["open", "fulfilled", "closed"],
			default: "open",
		},

		// ── Engagement ─────────────────────────────────────────────────────────────
		likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
		likeCount: {
			type: Number,
			default: 0,
			// Denormalised for fast sorting; updated via post-save hook
		},
		commentCount: {
			type: Number,
			default: 0,
		},

		// ── Key reference ──────────────────────────────────────────────────────────
		keyVersion: {
			type: Number,
			default: 1,
			// Matches User.keyVersion at time of encryption — needed for re-encryption
			// after key rotation
		},

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
			// HMAC-SHA256 over (encryptedTitle + encryptedContent + author + createdAt)
		},

		// ── Moderation ─────────────────────────────────────────────────────────────
		isDeleted: {
			type: Boolean,
			default: false,
			// Soft-delete — admins can restore; hard-delete via cron
		},
		deletedBy: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			default: null,
		},
		deletedAt: {
			type: Date,
			default: null,
		},
	},
	{
		timestamps: true,
	},
);

// ── Indexes ────────────────────────────────────────────────────────────────────
PostSchema.index({ author: 1, createdAt: -1 });
PostSchema.index({ category: 1, createdAt: -1 });
PostSchema.index({ status: 1 });
PostSchema.index({ tags: 1 });
PostSchema.index({ isDeleted: 1 });
PostSchema.index({ likeCount: -1 });

export default mongoose.model("Post", PostSchema);
