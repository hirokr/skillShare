import mongoose from "mongoose";

const ConversationSchema = new mongoose.Schema(
	{
		participants: {
			type: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
			required: true,
			validate: {
				validator: (arr) => arr.length === 2,
				message: "A conversation must have exactly 2 participants",
			},
		},

		participantsKey: {
			type: String,
			required: true,
		},

		encryptedKeyForParticipant: [
			{
				userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
				encryptedKey: { type: String }, // RSA-OAEP encrypted nonce, base64
			},
		],

		// ── Last message snapshot (for conversation list UI) ──────────────────────
		lastMessageAt: {
			type: Date,
			default: null,
		},
		lastMessagePreview: {
			type: String,
			default: null,
			// Intentionally left as a short encrypted snippet (first RSA block only)
			// so the inbox can show "New message" without full decryption
		},

		// ── Unread counters per participant ────────────────────────────────────────
		unreadCount: [
			{
				userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
				count: { type: Number, default: 0 },
			},
		],

		// ── State ──────────────────────────────────────────────────────────────────
		isActive: {
			type: Boolean,
			default: true,
		},
	},
	{
		timestamps: true,
	},
);

// Ensure only one conversation document per pair (order-independent)
ConversationSchema.index({ participantsKey: 1 }, { unique: true });
ConversationSchema.index({ participants: 1 });
ConversationSchema.index({ lastMessageAt: -1 });

const Conversation = mongoose.model("Conversation", ConversationSchema);

const MessageSchema = new mongoose.Schema(
	{
		// ── References ─────────────────────────────────────────────────────────────
		conversation: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "Conversation",
			required: true,
			index: true,
		},
		sender: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
		},
		recipient: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
		},

		// ── Double-encrypted content (RSA-OAEP) ───────────────────────────────────
		encryptedForSender: {
			type: String,
			required: true,
			// RSA-OAEP ciphertext using sender's public key
		},
		encryptedForRecipient: {
			type: String,
			required: true,
			// RSA-OAEP ciphertext using recipient's public key
		},

		// Chunk arrays for long messages
		chunksForSender: {
			type: [String],
			default: [],
		},
		chunksForRecipient: {
			type: [String],
			default: [],
		},

		// ── Media attachments ──────────────────────────────────────────────────────
		mediaUrls: {
			type: [String],
			default: [],
			// UploadThing URLs; not encrypted (metadata only, content is separate)
		},

		// ── Message type ───────────────────────────────────────────────────────────
		messageType: {
			type: String,
			enum: ["text", "media", "system"],
			default: "text",
		},

		// ── Delivery status ────────────────────────────────────────────────────────
		status: {
			type: String,
			enum: ["sent", "delivered", "read"],
			default: "sent",
		},
		readAt: {
			type: Date,
			default: null,
		},

		// ── Key reference ──────────────────────────────────────────────────────────
		senderKeyVersion: {
			type: Number,
			default: 1,
		},
		recipientKeyVersion: {
			type: Number,
			default: 1,
		},

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
			// HMAC-SHA256 over (encryptedForRecipient + sender + conversation + createdAt)
		},

		// ── Moderation ─────────────────────────────────────────────────────────────
		isDeleted: {
			type: Boolean,
			default: false,
		},
		deletedForSender: {
			type: Boolean,
			default: false,
		},
		deletedForRecipient: {
			type: Boolean,
			default: false,
		},
	},
	{
		timestamps: true,
	},
);

// ── Indexes ────────────────────────────────────────────────────────────────────
MessageSchema.index({ conversation: 1, createdAt: 1 });
MessageSchema.index({ sender: 1 });
MessageSchema.index({ recipient: 1, status: 1 });

const Message = mongoose.model("Message", MessageSchema);

export { Conversation, Message };
