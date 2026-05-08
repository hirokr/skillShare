/**
 * services/keyManager.js
 *
 * Key Management Module — satisfies CLAUDE.md Section 13.
 *
 * Responsibilities:
 *   - generateUserKeys(userId)         already called at registration; exposed
 *                                      here for completeness / re-keying
 *   - rotateKeys(userId, algorithm?)   generate new pair, archive old, update User
 *   - getPublicKey(userId, algorithm)  fetch the active public key for a user
 *   - checkAndRotateExpired()          scan KeyStore for expired keys and rotate
 *
 * Rotation flow (per CLAUDE.md §13):
 *   1. Generate new RSA + ECC key pair
 *   2. Create new KeyStore doc  (status: "active",  version: n+1)
 *   3. Archive old KeyStore doc (status: "archived", rotatedToVersion: n+1)
 *   4. Update User.publicKey / User.eccPublicKey / User.encryptedPrivateKey /
 *      User.encryptedEccPrivateKey / User.keyVersion / User.keyRotatedAt
 *
 * Re-encryption of old content is out of scope for this module — posts and
 * messages store keyVersion so a background job can re-encrypt them later.
 */

import { User, KeyStore } from "../models/index.js";
import rsa from "../crpyto/rsa.js";
import ecc from "../crpyto/ecc.js";
import { sign as signMac } from "../crpyto/hmac.js";

/** Key rotation interval in days (matches CLAUDE.md) */
const ROTATION_DAYS = 90;

// ─── Env helpers ──────────────────────────────────────────────────────────────

function requireEnv(name) {
	if (!process.env[name]) throw new Error(`Missing required env: ${name}`);
	return process.env[name];
}

function getServerRsaPublicKey() {
	return rsa.deserializePublicKey(requireEnv("SERVER_RSA_PUBLIC_KEY"));
}

function getServerRsaPrivateKey() {
	return rsa.deserializePrivateKey(requireEnv("SERVER_RSA_PRIVATE_KEY"));
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Compute the HMAC signature for a KeyStore document.
 */
function keyStoreMac(publicKey, encryptedPrivateKey, userId, version, algorithm) {
	return signMac(
		[publicKey, encryptedPrivateKey, userId.toString(), version, algorithm],
		requireEnv("HMAC_SERVER_KEY"),
	);
}

/**
 * Generate a new RSA key pair, chunk-encrypt the private key with the server
 * master RSA public key, and return serialised forms ready for storage.
 */
function makeRsaKeyPair(serverRsaPub) {
	const { publicKey, privateKey } = rsa.generateKeyPair();
	const serializedPub = rsa.serializePublicKey(publicKey);
	const serializedPriv = rsa.serializePrivateKey(privateKey);
	const encryptedPriv = JSON.stringify(rsa.chunkEncrypt(serializedPriv, serverRsaPub));
	return { serializedPub, encryptedPriv };
}

/**
 * Generate a new ECC key pair, chunk-encrypt the private key, and return
 * serialised forms ready for storage.
 */
function makeEccKeyPair(serverRsaPub) {
	const { publicKey, privateKey } = ecc.generateKeyPair();
	const serializedPub = ecc.serializePublicKey(publicKey);
	const serializedPriv = ecc.serializePrivateKey(privateKey);
	const encryptedPriv = JSON.stringify(rsa.chunkEncrypt(serializedPriv, serverRsaPub));
	return { serializedPub, encryptedPriv };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Retrieve the active public key for a user.
 *
 * @param {string} userId
 * @param {"RSA"|"ECC"} algorithm
 * @returns {Promise<string>}  serialised public key string
 */
export async function getPublicKey(userId, algorithm = "RSA") {
	const entry = await KeyStore.findOne({
		user: userId,
		algorithm,
		status: "active",
	}).sort({ version: -1 });

	if (!entry) {
		throw new Error(`No active ${algorithm} key found for user ${userId}`);
	}
	return entry.publicKey;
}

/**
 * Rotate keys for a single user.
 *
 * Generates fresh RSA + ECC key pairs (or just one algorithm if specified),
 * archives the old KeyStore entries, creates new ones, and updates the User
 * document atomically.
 *
 * @param {string}          userId
 * @param {"RSA"|"ECC"|"both"} [algorithm="both"]
 * @returns {Promise<{ newKeyVersion: number }>}
 */
export async function rotateKeys(userId, algorithm = "both") {
	const user = await User.findById(userId).select(
		"publicKey eccPublicKey encryptedPrivateKey encryptedEccPrivateKey keyVersion",
	);
	if (!user) throw new Error("User not found");

	const serverRsaPub = getServerRsaPublicKey();
	const hmacKey = requireEnv("HMAC_SERVER_KEY");
	const newVersion = (user.keyVersion || 1) + 1;
	const now = new Date();
	const expiresAt = new Date(now.getTime() + ROTATION_DAYS * 24 * 60 * 60 * 1000);

	const userUpdate = { keyVersion: newVersion, keyRotatedAt: now };

	// ── RSA rotation ──────────────────────────────────────────────────────────
	if (algorithm === "RSA" || algorithm === "both") {
		// Archive old active RSA key
		const oldRsa = await KeyStore.findOne({ user: userId, algorithm: "RSA", status: "active" })
			.sort({ version: -1 });

		if (oldRsa) {
			oldRsa.status = "archived";
			oldRsa.rotatedToVersion = newVersion;
			await oldRsa.save();
		}

		// Generate and store new RSA key
		const { serializedPub, encryptedPriv } = makeRsaKeyPair(serverRsaPub);
		const mac = keyStoreMac(serializedPub, encryptedPriv, userId, newVersion, "RSA");

		await KeyStore.create({
			user: userId,
			algorithm: "RSA",
			version: newVersion,
			publicKey: serializedPub,
			encryptedPrivateKey: encryptedPriv,
			keySize: 2048,
			status: "active",
			activatedAt: now,
			expiresAt,
			hmacSignature: mac,
		});

		userUpdate.publicKey = serializedPub;
		userUpdate.encryptedPrivateKey = encryptedPriv;
	}

	// ── ECC rotation ──────────────────────────────────────────────────────────
	if (algorithm === "ECC" || algorithm === "both") {
		const oldEcc = await KeyStore.findOne({ user: userId, algorithm: "ECC", status: "active" })
			.sort({ version: -1 });

		if (oldEcc) {
			oldEcc.status = "archived";
			oldEcc.rotatedToVersion = newVersion;
			await oldEcc.save();
		}

		const { serializedPub, encryptedPriv } = makeEccKeyPair(serverRsaPub);
		const mac = keyStoreMac(serializedPub, encryptedPriv, userId, newVersion, "ECC");

		await KeyStore.create({
			user: userId,
			algorithm: "ECC",
			version: newVersion,
			publicKey: serializedPub,
			encryptedPrivateKey: encryptedPriv,
			keySize: 256,
			curve: "secp256k1",
			status: "active",
			activatedAt: now,
			expiresAt,
			hmacSignature: mac,
		});

		userUpdate.eccPublicKey = serializedPub;
		userUpdate.encryptedEccPrivateKey = encryptedPriv;
	}

	await User.updateOne({ _id: userId }, { $set: userUpdate });

	return { newKeyVersion: newVersion };
}

/**
 * Revoke a specific key version for a user (admin action).
 * Sets KeyStore status to "revoked" — content encrypted with this key
 * becomes inaccessible (intentional, per CLAUDE.md §13).
 *
 * @param {string} userId
 * @param {"RSA"|"ECC"} algorithm
 * @param {number} version
 */
export async function revokeKey(userId, algorithm, version) {
	const entry = await KeyStore.findOne({ user: userId, algorithm, version });
	if (!entry) throw new Error("Key not found");
	if (entry.status === "revoked") throw new Error("Key already revoked");

	entry.status = "revoked";
	entry.revokedAt = new Date();
	await entry.save();
}

/**
 * Scan the KeyStore collection for keys whose `expiresAt` has passed and
 * rotate them. Called on server startup and can be invoked by the cron script.
 *
 * @returns {Promise<{ rotated: number, errors: number }>}
 */
export async function checkAndRotateExpired() {
	const now = new Date();

	// Find all active keys that have passed their expiry date
	const expired = await KeyStore.find({
		status: "active",
		expiresAt: { $lte: now },
	}).select("user algorithm version");

	// Deduplicate by userId — one rotation covers both RSA + ECC
	const userIdsSeen = new Set();
	const uniqueUsers = [];
	for (const entry of expired) {
		const id = entry.user.toString();
		if (!userIdsSeen.has(id)) {
			userIdsSeen.add(id);
			uniqueUsers.push(id);
		}
	}

	let rotated = 0;
	let errors = 0;

	for (const userId of uniqueUsers) {
		try {
			await rotateKeys(userId, "both");
			rotated++;
			console.log(`[keyManager] Rotated keys for user ${userId}`);
		} catch (err) {
			errors++;
			console.error(`[keyManager] Failed to rotate keys for user ${userId}:`, err?.message);
		}
	}

	if (uniqueUsers.length > 0) {
		console.log(`[keyManager] Rotation complete — rotated: ${rotated}, errors: ${errors}`);
	}

	return { rotated, errors };
}

/**
 * Return full KeyStore history for a user (admin use).
 *
 * @param {string} userId
 * @returns {Promise<object[]>}
 */
export async function getKeyHistory(userId) {
	return KeyStore.find({ user: userId })
		.sort({ algorithm: 1, version: -1 })
		.select("-encryptedPrivateKey -hmacSignature")
		.lean();
}

export default {
	getPublicKey,
	rotateKeys,
	revokeKey,
	checkAndRotateExpired,
	getKeyHistory,
};