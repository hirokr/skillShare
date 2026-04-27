import mongoose from "mongoose";

/**
 * COMMENT MODEL
 *
 * Comments appear on posts. Supports nested replies (one level deep —
 * parentComment field). Deeper threading would require a recursive tree.
 *
 * Encryption strategy:
 *  - encryptedContent → RSA-OAEP encrypted comment text
 *  - hmacSignature    → HMAC-SHA256 over (encryptedContent + author + postId)
 */
const CommentSchema = new mongoose.Schema(
	{
		// ── References ─────────────────────────────────────────────────────────────
		post: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Post",
			required: true,
			index: true,
		},
		author: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
		},
		parentComment: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Comment",
			default: null,
			// null = top-level comment; set = reply to another comment
		},

		// ── Encrypted content (RSA-OAEP) ──────────────────────────────────────────
		encryptedContent: {
			type: String,
			required: true,
		},
		encryptedChunks: {
			type: [String],
			default: [],
			// Overflow chunks if content exceeds single RSA block
		},

		// ── Key reference ──────────────────────────────────────────────────────────
		keyVersion: {
			type: Number,
			default: 1,
		},

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
		},

		// ── Engagement ─────────────────────────────────────────────────────────────
		likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
		likeCount: {
			type: Number,
			default: 0,
		},
		replyCount: {
			type: Number,
			default: 0,
		},

		// ── Moderation ─────────────────────────────────────────────────────────────
		isDeleted: {
			type: Boolean,
			default: false,
		},
		deletedBy: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			default: null,
		},
	},
	{
		timestamps: true,
	},
);

// ── Indexes ────────────────────────────────────────────────────────────────────
CommentSchema.index({ post: 1, createdAt: 1 });
CommentSchema.index({ parentComment: 1 });
CommentSchema.index({ author: 1 });

export default mongoose.model("Comment", CommentSchema);
