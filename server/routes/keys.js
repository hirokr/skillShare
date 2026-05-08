/**
 * routes/keys.js
 *
 * Key management endpoints.
 *
 * Public:
 *   GET  /keys/public/:userId          — fetch active public key (RSA or ECC)
 *
 * Authenticated (any user — own keys only):
 *   POST /keys/rotate                  — rotate own keys
 *   GET  /keys/history                 — view own KeyStore history
 *
 * Admin only:
 *   POST /keys/rotate/:userId          — force-rotate any user's keys
 *   POST /keys/revoke/:userId          — revoke a specific key version
 *   GET  /keys/history/:userId         — view any user's KeyStore history
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import {
	getPublicKey,
	rotateKeys,
	revokeKey,
	getKeyHistory,
} from "../services/keyManager.js";

const router = express.Router();

// ─── Authorisation helper ─────────────────────────────────────────────────────

function requireAdmin(req, res, next) {
	if (req.user?.role !== "admin") {
		return res.status(403).json({ message: "Admin access required" });
	}
	return next();
}

// ─── GET /keys/public/:userId?algorithm=RSA ───────────────────────────────────
// Returns the active public key for any user. No auth required — public keys
// are meant to be freely distributed (CLAUDE.md §13).

router.get("/public/:userId", async (req, res) => {
	try {
		const { userId } = req.params;
		const algorithm = req.query.algorithm === "ECC" ? "ECC" : "RSA";

		const publicKey = await getPublicKey(userId, algorithm);
		return res.status(200).json({ userId, algorithm, publicKey });
	} catch (err) {
		const status = err.message?.includes("not found") ? 404 : 500;
		return res.status(status).json({ message: err.message || "Failed to fetch public key" });
	}
});

// ─── POST /keys/rotate ────────────────────────────────────────────────────────
// Rotate the authenticated user's own keys.

router.post("/rotate", authenticate, async (req, res) => {
	try {
		const userId = req.user.id;
		const algorithm = ["RSA", "ECC", "both"].includes(req.body?.algorithm)
			? req.body.algorithm
			: "both";

		const { newKeyVersion } = await rotateKeys(userId, algorithm);
		return res.status(200).json({
			message: "Keys rotated successfully",
			newKeyVersion,
			algorithm,
		});
	} catch (err) {
		return res.status(500).json({ message: err.message || "Key rotation failed" });
	}
});

// ─── GET /keys/history ────────────────────────────────────────────────────────
// View own KeyStore history (excludes private key material).

router.get("/history", authenticate, async (req, res) => {
	try {
		const history = await getKeyHistory(req.user.id);
		return res.status(200).json({ history });
	} catch (err) {
		return res.status(500).json({ message: err.message || "Failed to fetch key history" });
	}
});

// ─── POST /keys/rotate/:userId  (admin) ───────────────────────────────────────
// Force-rotate any user's keys.

router.post("/rotate/:userId", authenticate, requireAdmin, async (req, res) => {
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

// ─── POST /keys/revoke/:userId  (admin) ───────────────────────────────────────
// Revoke a specific key version. Content encrypted with that key becomes
// inaccessible — this is intentional per CLAUDE.md §13.

router.post("/revoke/:userId", authenticate, requireAdmin, async (req, res) => {
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
		return res.status(200).json({
			message: "Key revoked",
			userId,
			algorithm,
			version: Number(version),
		});
	} catch (err) {
		const status = err.message?.includes("not found") ? 404 : 500;
		return res.status(status).json({ message: err.message || "Key revocation failed" });
	}
});

// ─── GET /keys/history/:userId  (admin) ───────────────────────────────────────

router.get("/history/:userId", authenticate, requireAdmin, async (req, res) => {
	try {
		const history = await getKeyHistory(req.params.userId);
		return res.status(200).json({ history });
	} catch (err) {
		return res.status(500).json({ message: err.message || "Failed to fetch key history" });
	}
});

export default router;