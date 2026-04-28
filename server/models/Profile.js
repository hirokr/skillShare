import mongoose from "mongoose";
/**
 * PROFILE MODEL
 *
 * Extended public-facing profile data for each user.
 * Kept separate from User to avoid loading sensitive auth fields
 * on every profile page request.
 *
 * Encryption strategy:
 *  - encryptedBio, encryptedLocation, encryptedWebsite → ECC/ECIES encrypted
 *  - displayName → stored plaintext (chosen to be public)
 *  - hmacSignature → HMAC over all encrypted fields
 */
const ProfileSchema = new mongoose.Schema(
	{
		// ── Owner ──────────────────────────────────────────────────────────────────
		user: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
			unique: true,
		},

		// ── Public display fields (plaintext — user chose to make these public) ────
		displayName: {
			type: String,
			default: "",
			// Shown on profile card; not sensitive
		},
		avatarUrl: {
			type: String,
			default: null,
			// UploadThing URL
		},
		bannerUrl: {
			type: String,
			default: null,
		},

		// ── Encrypted profile fields (ECC/ECIES) ──────────────────────────────────
		encryptedBio: {
			type: String,
			default: null,
		},
		encryptedSkills: {
			type: String,
			default: null,
		},
		encryptedLocation: {
			type: String,
			default: null,
		},
		encryptedWebsite: {
			type: String,
			default: null,
		},
		encryptedOccupation: {
			type: String,
			default: null,
		},

		// ── Privacy settings ───────────────────────────────────────────────────────
		privacy: {
			showEmail: { type: Boolean, default: false },
			showContact: { type: Boolean, default: false },
			showLocation: { type: Boolean, default: true },
			allowMessages: { type: Boolean, default: true },
			// allowMessages: false blocks DM requests from non-followers
		},

		// ── Stats (denormalised for fast profile renders) ──────────────────────────
		postCount: { type: Number, default: 0 },
		followerCount: { type: Number, default: 0 },
		followingCount: { type: Number, default: 0 },

		// ── Integrity (MAC) ────────────────────────────────────────────────────────
		hmacSignature: {
			type: String,
			required: true,
			// HMAC over (encryptedBio + encryptedSkills + encryptedLocation + encryptedWebsite + userId)
		},

		// ── Key version reference ──────────────────────────────────────────────────
		keyVersion: {
			type: Number,
			default: 1,
		},
	},
	{
		timestamps: true,
	},
);

ProfileSchema.index({ user: 1 });

export default mongoose.model("Profile", ProfileSchema);
