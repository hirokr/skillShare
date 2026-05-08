/**
 * routes/admin.js
 *
 * Admin-only endpoints. Every route requires a valid session AND role === "admin".
 *
 *   GET  /admin/users                  — paginated user list (decrypted names)
 *   GET  /admin/users/:userId          — single user detail
 *   POST /admin/users/:userId/ban      — deactivate a user (soft-ban)
 *   POST /admin/users/:userId/unban    — reactivate a user
 *   POST /admin/keys/rotate/:userId    — force-rotate a user's keys (delegates to keyManager)
 *   POST /admin/keys/revoke/:userId    — revoke a specific key version
 *   GET  /admin/keys/history/:userId   — key history for any user
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import { User } from "../models/index.js";
import ecc from "../crpyto/ecc.js";
import { rotateKeys, revokeKey, getKeyHistory } from "../services/keyManager.js";

const router = express.Router();

// ─── Guard: every route in this file requires admin ──────────────────────────

function requireAdmin(req, res, next) {
	if (req.user?.role !== "admin") {
		return res.status(403).json({ message: "Admin access required" });
	}
	return next();
}

router.use(authenticate, requireAdmin);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function requireEnv(name) {
	if (!process.env[name]) throw new Error(`Missing env: ${name}`);
	return process.env[name];
}

function getServerEccPrivateKey() {
	return ecc.deserializePrivateKey(requireEnv("SERVER_ECC_PRIVATE_KEY"));
}

function safeDecrypt(ciphertext, privKey) {
	if (!ciphertext) return null;
	try {
		return ecc.decrypt(ciphertext, privKey);
	} catch {
		return null;
	}
}

function formatUser(user, eccPriv) {
	return {
		id: user._id.toString(),
		username: safeDecrypt(user.encryptedUsername, eccPriv),
		email: safeDecrypt(user.encryptedEmail, eccPriv),
		contact: safeDecrypt(user.encryptedContact, eccPriv),
		role: user.role,
		isActive: user.isActive,
		twoFactorEnabled: user.twoFactorEnabled,
		keyVersion: user.keyVersion,
		keyRotatedAt: user.keyRotatedAt,
		lastLoginAt: user.lastLoginAt,
		createdAt: user.createdAt,
	};
}

// ─── GET /admin/users ─────────────────────────────────────────────────────────
// Returns a paginated, decrypted list of all users.
// Query params: page (default 1), limit (default 20), search (optional username filter)

router.get("/users", async (req, res) => {
	try {
		const page = Math.max(1, parseInt(req.query.page) || 1);
		const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
		const skip = (page - 1) * limit;

		const [users, total] = await Promise.all([
			User.find()
				.select(
					"encryptedUsername encryptedEmail encryptedContact role isActive twoFactorEnabled keyVersion keyRotatedAt lastLoginAt createdAt",
				)
				.sort({ createdAt: -1 })
				.skip(skip)
				.limit(limit),
			User.countDocuments(),
		]);

		const eccPriv = getServerEccPrivateKey();
		const formatted = users.map((u) => formatUser(u, eccPriv));

		return res.status(200).json({
			users: formatted,
			pagination: {
				page,
				limit,
				total,
				totalPages: Math.ceil(total / limit),
			},
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to fetch users" });
	}
});

// ─── GET /admin/users/:userId ─────────────────────────────────────────────────

router.get("/users/:userId", async (req, res) => {
	try {
		const user = await User.findById(req.params.userId).select(
			"encryptedUsername encryptedEmail encryptedContact role isActive twoFactorEnabled keyVersion keyRotatedAt lastLoginAt createdAt",
		);
		if (!user) return res.status(404).json({ message: "User not found" });

		const eccPriv = getServerEccPrivateKey();
		return res.status(200).json({ user: formatUser(user, eccPriv) });
	} catch (error) {
		return res.status(500).json({ message: "Failed to fetch user" });
	}
});

// ─── POST /admin/users/:userId/ban ────────────────────────────────────────────

router.post("/users/:userId/ban", async (req, res) => {
	try {
		const { userId } = req.params;
		if (userId === req.user.id) {
			return res.status(400).json({ message: "Cannot ban yourself" });
		}

		const user = await User.findById(userId);
		if (!user) return res.status(404).json({ message: "User not found" });
		if (!user.isActive) return res.status(400).json({ message: "User is already banned" });

		user.isActive = false;
		user.refreshTokenHash = null; // invalidate all sessions
		user.tokenVersion = (user.tokenVersion || 0) + 1;
		await user.save();

		return res.status(200).json({ message: "User banned", userId });
	} catch (error) {
		return res.status(500).json({ message: "Failed to ban user" });
	}
});

// ─── POST /admin/users/:userId/unban ─────────────────────────────────────────

router.post("/users/:userId/unban", async (req, res) => {
	try {
		const { userId } = req.params;
		const user = await User.findById(userId);
		if (!user) return res.status(404).json({ message: "User not found" });
		if (user.isActive) return res.status(400).json({ message: "User is not banned" });

		user.isActive = true;
		await user.save();

		return res.status(200).json({ message: "User unbanned", userId });
	} catch (error) {
		return res.status(500).json({ message: "Failed to unban user" });
	}
});

// ─── POST /admin/keys/rotate/:userId ─────────────────────────────────────────

router.post("/keys/rotate/:userId", async (req, res) => {
	try {
		const { userId } = req.params;
		const algorithm = ["RSA", "ECC", "both"].includes(req.body?.algorithm)
			? req.body.algorithm
			: "both";

		const { newKeyVersion } = await rotateKeys(userId, algorithm);
		return res.status(200).json({
			message: "Keys rotated successfully",
			userId,
			newKeyVersion,
			algorithm,
		});
	} catch (err) {
		const status = err.message?.includes("not found") ? 404 : 500;
		return res.status(status).json({ message: err.message || "Key rotation failed" });
	}
});

// ─── POST /admin/keys/revoke/:userId ─────────────────────────────────────────

router.post("/keys/revoke/:userId", async (req, res) => {
	try {
		const { userId } = req.params;
		const { algorithm, version } = req.body || {};

		if (!algorithm || !version) {
			return res.status(400).json({ message: "algorithm and version are required" });
		}
		if (!["RSA", "ECC"].includes(algorithm)) {
			return res.status(400).json({ message: "algorithm must be RSA or ECC" });
		}

		await revokeKey(userId, algorithm, Number(version));
		return res.status(200).json({ message: "Key revoked", userId, algorithm, version: Number(version) });
	} catch (err) {
		const status = err.message?.includes("not found") ? 404 : 500;
		return res.status(status).json({ message: err.message || "Key revocation failed" });
	}
});

// ─── GET /admin/keys/history/:userId ─────────────────────────────────────────

router.get("/keys/history/:userId", async (req, res) => {
	try {
		const history = await getKeyHistory(req.params.userId);
		return res.status(200).json({ history });
	} catch (err) {
		return res.status(500).json({ message: err.message || "Failed to fetch key history" });
	}
});

export default router;