/**
 * controllers/authController.js
 * User authentication with two-step verification (2FA via TOTP).
 *
 * Login flow:
 *   Step 1 — POST /auth/login      { email, password }
 *            → 200 { requires2FA: true, tempToken }   (if 2FA enabled)
 *            → 200 { accessToken, userId }             (if 2FA disabled)
 *
 *   Step 2 — POST /auth/2fa/verify { tempToken, totpCode }
 *            → 200 { accessToken, userId }
 *
 * 2FA management (authenticated):
 *   POST /auth/2fa/setup            → { otpauthUrl }
 *   POST /auth/2fa/confirm          { totpCode }
 *   POST /auth/2fa/disable          { totpCode }
 */
 
import { User, Profile, KeyStore } from "../models/index.js";
import rsa from "../crpyto/rsa.js";
import ecc from "../crpyto/ecc.js";
import { sign as signMac } from "../crpyto/hmac.js";
import {
	generateSalt,
	hashPassword,
	verifyPassword,
	hashField,
	hashToken,
} from "../crpyto/hash.js";
import { randomBytes, toHex } from "../crpyto/utils.js";
import { signJwt, verifyJwt } from "../utils/jwt.js";
import {
	generateSecret,
	verifyTotp,
	buildOtpAuthUrl,
} from "../crpyto/totp.js";
 
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ACCESS_TOKEN_COOKIE = "accessToken";
const REFRESH_TOKEN_COOKIE = "refreshToken";
 
// ─── Input validators ──────────────────────────────────────────────────────
 
function passwordStrengthError(password) {
	if (!/[a-z]/.test(password))
		return "Password must include a lowercase letter";
	if (!/[A-Z]/.test(password))
		return "Password must include an uppercase letter";
	if (!/[0-9]/.test(password)) return "Password must include a number";
	if (!/[^A-Za-z0-9]/.test(password)) return "Password must include a symbol";
	return null;
}
 
function validateRegisterInput({ username, email, password, contact }) {
	if (!username || !email || !password) return "Missing required fields";
	if (!EMAIL_REGEX.test(email)) return "Invalid email format";
	if (password.length < 8 || password.length > 128)
		return "Password must be 8-128 characters";
	const strengthError = passwordStrengthError(password);
	if (strengthError) return strengthError;
	if (username.length < 3 || username.length > 32)
		return "Username must be 3-32 characters";
	if (contact && contact.length > 64) return "Contact is too long";
	return null;
}
 
function validateLoginInput({ email, password }) {
	if (!email || !password) return "Missing email or password";
	if (!EMAIL_REGEX.test(email)) return "Invalid email format";
	if (password.length < 8 || password.length > 128)
		return "Invalid password length";
	return null;
}
 
function validatePasswordChangeInput({ currentPassword, newPassword }) {
	if (!currentPassword || !newPassword) return "Missing password fields";
	if (newPassword.length < 8 || newPassword.length > 128)
		return "Password must be 8-128 characters";
	const strengthError = passwordStrengthError(newPassword);
	if (strengthError) return strengthError;
	return null;
}
 
// ─── Cookie helpers ────────────────────────────────────────────────────────
 
function getCookieOptions() {
	const isProd = process.env.NODE_ENV === "production";
	return { httpOnly: true, secure: isProd, sameSite: "strict", path: "/" };
}
function setAccessTokenCookie(res, token) {
	res.cookie(ACCESS_TOKEN_COOKIE, token, {
		...getCookieOptions(),
		maxAge: 15 * 60 * 1000,
	});
}
function setRefreshTokenCookie(res, token) {
	res.cookie(REFRESH_TOKEN_COOKIE, token, {
		...getCookieOptions(),
		maxAge: 7 * 24 * 60 * 60 * 1000,
	});
}
function clearAccessTokenCookie(res) {
	res.clearCookie(ACCESS_TOKEN_COOKIE, getCookieOptions());
}
function clearRefreshTokenCookie(res) {
	res.clearCookie(REFRESH_TOKEN_COOKIE, getCookieOptions());
}
function getCookieToken(cookieHeader, name) {
	if (!cookieHeader) return null;
	for (const part of cookieHeader.split(";")) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) return rest.join("=") || null;
	}
	return null;
}
 
// ─── Env / key helpers ─────────────────────────────────────────────────────
 
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
function getServerEccPublicKey() {
	return ecc.deserializePublicKey(requireEnv("SERVER_ECC_PUBLIC_KEY"));
}
function generateRefreshToken() {
	return toHex(randomBytes(32));
}
 
// ─── Temp token (short-lived JWT for 2FA step) ────────────────────────────
//
// After password is verified but before 2FA is confirmed, we issue a
// 2-minute "temp token" (purpose:"2fa") so the second step can identify
// the user without granting a full session yet.
 
const TEMP_TOKEN_TTL = 120; // seconds
 
function signTempToken(userId) {
	return signJwt(
		{ userId, purpose: "2fa" },
		requireEnv("JWT_SECRET"),
		TEMP_TOKEN_TTL,
	);
}
 
function verifyTempToken(token) {
	if (!token) return null;
	const { valid, payload } = verifyJwt(token, requireEnv("JWT_SECRET"));
	if (!valid || payload?.purpose !== "2fa" || !payload?.userId) return null;
	return payload.userId;
}
 
// ─────────────────────────────────────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────────────────────────────────────
 
export async function register(req, res) {
	try {
		const { username, email, password, contact } = req.body || {};
		const err = validateRegisterInput({ username, email, password, contact });
		if (err) return res.status(400).json({ message: err });
 
		const cleanUsername = username.trim();
		const cleanEmail = email.trim().toLowerCase();
		const cleanContact = contact ? contact.trim() : "12390123";
 
		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const usernameHash = hashField(cleanUsername, hmacKey);
		const emailHash = hashField(cleanEmail, hmacKey);
 
		const existing = await User.findOne({ $or: [{ usernameHash }, { emailHash }] });
		if (existing) return res.status(409).json({ message: "User already exists" });
 
		const existingUserCount = await User.countDocuments();
		const role = existingUserCount === 0 ? "admin" : "user";
 
		const salt = generateSalt();
		const passwordHash = hashPassword(password, salt);
 
		const serverRsaPub = getServerRsaPublicKey();
		const serverEccPub = getServerEccPublicKey();
 
		const { publicKey: userRsaPub, privateKey: userRsaPriv } = rsa.generateKeyPair();
		const { publicKey: userEccPub, privateKey: userEccPriv } = ecc.generateKeyPair();
 
		const encryptedUsername = ecc.encrypt(cleanUsername, serverEccPub);
		const encryptedEmail = ecc.encrypt(cleanEmail, serverEccPub);
		const encryptedContact = cleanContact ? ecc.encrypt(cleanContact, serverEccPub) : null;
 
		const serializedRsaPub = rsa.serializePublicKey(userRsaPub);
		const serializedRsaPriv = rsa.serializePrivateKey(userRsaPriv);
		const serializedEccPub = ecc.serializePublicKey(userEccPub);
		const serializedEccPriv = ecc.serializePrivateKey(userEccPriv);
 
		const encryptedPrivateKey = JSON.stringify(rsa.chunkEncrypt(serializedRsaPriv, serverRsaPub));
		const encryptedEccPrivateKey = JSON.stringify(rsa.chunkEncrypt(serializedEccPriv, serverRsaPub));
 
		const hmacSignature = signMac([encryptedUsername, encryptedEmail, encryptedContact], hmacKey);
 
		const user = await User.create({
			encryptedUsername, encryptedEmail, encryptedContact,
			usernameHash, emailHash, passwordHash, passwordSalt: salt,
			publicKey: serializedRsaPub, encryptedPrivateKey,
			eccPublicKey: serializedEccPub, encryptedEccPrivateKey,
			hmacSignature, role,
		});
 
		const profileMac = signMac([null, null, null, null, user._id.toString()], hmacKey);
		await Profile.create({ user: user._id, hmacSignature: profileMac });
 
		const keyStoreRsaMac = signMac([serializedRsaPub, encryptedPrivateKey, user._id.toString(), 1, "RSA"], hmacKey);
		await KeyStore.create({
			user: user._id, algorithm: "RSA", version: 1,
			publicKey: serializedRsaPub, encryptedPrivateKey, keySize: 2048,
			hmacSignature: keyStoreRsaMac,
		});
 
		const keyStoreEccMac = signMac([serializedEccPub, encryptedEccPrivateKey, user._id.toString(), 1, "ECC"], hmacKey);
		await KeyStore.create({
			user: user._id, algorithm: "ECC", version: 1,
			publicKey: serializedEccPub, encryptedPrivateKey: encryptedEccPrivateKey,
			keySize: 256, curve: "secp256k1", hmacSignature: keyStoreEccMac,
		});
 
		const accessToken = signJwt(
			{ userId: user._id.toString(), role: user.role, tokenVersion: 0 },
			requireEnv("JWT_SECRET"), 15 * 60,
		);
		const refreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(refreshToken);
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, refreshToken);
 
		return res.status(201).json({ message: "Registered", accessToken, userId: user._id });
	} catch (error) {
		return res.status(500).json({ message: "Registration failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// LOGIN  (Step 1 of 2-step verification)
// POST /auth/login  { email, password }
// ─────────────────────────────────────────────────────────────────────────────
 
export async function login(req, res) {
	try {
		const { email, password } = req.body || {};
		const err = validateLoginInput({ email, password });
		if (err) return res.status(400).json({ message: err });
 
		const cleanEmail = email.trim().toLowerCase();
		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const emailHash = hashField(cleanEmail, hmacKey);
 
		const user = await User.findOne({ emailHash, isActive: true });
		if (!user) return res.status(401).json({ message: "Invalid credentials" });
 
		// ── Factor 1: password ────────────────────────────────────────────────
		const ok = verifyPassword(password, user.passwordSalt, user.passwordHash);
		if (!ok) return res.status(401).json({ message: "Invalid credentials" });
 
		// ── Factor 2 required: return a short-lived temp token ────────────────
		if (user.twoFactorEnabled && user.encryptedTwoFactorSecret) {
			const tempToken = signTempToken(user._id.toString());
			return res.status(200).json({ requires2FA: true, tempToken });
		}
 
		// ── No 2FA configured: issue full session immediately ─────────────────
		const accessToken = signJwt(
			{ userId: user._id.toString(), role: user.role, tokenVersion: user.tokenVersion || 0 },
			requireEnv("JWT_SECRET"), 15 * 60,
		);
		const refreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(refreshToken);
		user.lastLoginAt = new Date();
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, refreshToken);
 
		return res.status(200).json({ message: "Logged in", accessToken, userId: user._id });
	} catch (error) {
		return res.status(500).json({ message: "Login failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// VERIFY 2FA  (Step 2 of 2-step verification)
// POST /auth/2fa/verify  { tempToken, totpCode }
// ─────────────────────────────────────────────────────────────────────────────
 
export async function verify2FA(req, res) {
	try {
		const { tempToken, totpCode } = req.body || {};
 
		if (!tempToken || !totpCode) {
			return res.status(400).json({ message: "Missing temp token or TOTP code" });
		}
 
		// Validate short-lived token issued after password check
		const userId = verifyTempToken(tempToken);
		if (!userId) {
			return res.status(401).json({ message: "Invalid or expired verification token" });
		}
 
		const user = await User.findById(userId).select(
			"twoFactorEnabled encryptedTwoFactorSecret role tokenVersion isActive",
		);
		if (!user || !user.isActive) {
			return res.status(401).json({ message: "User not found" });
		}
		if (!user.twoFactorEnabled || !user.encryptedTwoFactorSecret) {
			return res.status(400).json({ message: "2FA is not enabled for this account" });
		}
 
		// Decrypt the RSA-encrypted TOTP secret
		const serverPriv = getServerRsaPrivateKey();
		const secretHex = rsa.chunkDecrypt(
			JSON.parse(user.encryptedTwoFactorSecret),
			serverPriv,
		);
 
		// ── Factor 2: TOTP code ───────────────────────────────────────────────
		const valid = verifyTotp(totpCode, secretHex);
		if (!valid) {
			return res.status(401).json({ message: "Invalid authentication code" });
		}
 
		// Both factors verified — issue full session
		const accessToken = signJwt(
			{ userId: user._id.toString(), role: user.role, tokenVersion: user.tokenVersion || 0 },
			requireEnv("JWT_SECRET"), 15 * 60,
		);
		const refreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(refreshToken);
		user.lastLoginAt = new Date();
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, refreshToken);
 
		return res.status(200).json({ message: "Logged in", accessToken, userId: user._id });
	} catch (error) {
		return res.status(500).json({ message: "2FA verification failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// SETUP 2FA  (authenticated — generates secret, returns otpauth:// URI)
// POST /auth/2fa/setup
// ─────────────────────────────────────────────────────────────────────────────
 
export async function setup2FA(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) return res.status(401).json({ message: "Unauthorized" });
 
		const user = await User.findById(userId).select(
			"twoFactorEnabled encryptedEmail",
		);
		if (!user) return res.status(404).json({ message: "User not found" });
		if (user.twoFactorEnabled) {
			return res.status(400).json({ message: "2FA is already enabled" });
		}
 
		const secretHex = generateSecret();
		const serverRsaPub = getServerRsaPublicKey();
		const encryptedTwoFactorSecret = JSON.stringify(
			rsa.chunkEncrypt(secretHex, serverRsaPub),
		);
 
		// Persist encrypted secret (not yet active — user must confirm via /2fa/confirm)
		user.encryptedTwoFactorSecret = encryptedTwoFactorSecret;
		await user.save();
 
		// Try to get a readable label for the QR URI
		let label = "user";
		try {
			const serverEccPriv = ecc.deserializePrivateKey(requireEnv("SERVER_ECC_PRIVATE_KEY"));
			label = ecc.decrypt(user.encryptedEmail, serverEccPriv);
		} catch { /* non-fatal — label is cosmetic */ }
 
		const otpauthUrl = buildOtpAuthUrl(secretHex, label);
 
		return res.status(200).json({
			message: "Scan the QR code with your authenticator app, then call /auth/2fa/confirm.",
			otpauthUrl,
		});
	} catch (error) {
		return res.status(500).json({ message: "2FA setup failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// CONFIRM 2FA  (authenticated — activates 2FA after first successful verify)
// POST /auth/2fa/confirm  { totpCode }
// ─────────────────────────────────────────────────────────────────────────────
 
export async function confirm2FA(req, res) {
	try {
		const userId = req.user?.id;
		const { totpCode } = req.body || {};
		if (!userId) return res.status(401).json({ message: "Unauthorized" });
		if (!totpCode) return res.status(400).json({ message: "Missing TOTP code" });
 
		const user = await User.findById(userId).select(
			"twoFactorEnabled encryptedTwoFactorSecret",
		);
		if (!user) return res.status(404).json({ message: "User not found" });
		if (user.twoFactorEnabled) {
			return res.status(400).json({ message: "2FA is already enabled" });
		}
		if (!user.encryptedTwoFactorSecret) {
			return res.status(400).json({ message: "Call /auth/2fa/setup first" });
		}
 
		const serverPriv = getServerRsaPrivateKey();
		const secretHex = rsa.chunkDecrypt(
			JSON.parse(user.encryptedTwoFactorSecret), serverPriv,
		);
		if (!verifyTotp(totpCode, secretHex)) {
			return res.status(401).json({ message: "Invalid authentication code" });
		}
 
		user.twoFactorEnabled = true;
		await user.save();
		return res.status(200).json({ message: "Two-factor authentication enabled" });
	} catch (error) {
		return res.status(500).json({ message: "2FA confirmation failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// DISABLE 2FA  (authenticated — requires current TOTP to disable)
// POST /auth/2fa/disable  { totpCode }
// ─────────────────────────────────────────────────────────────────────────────
 
export async function disable2FA(req, res) {
	try {
		const userId = req.user?.id;
		const { totpCode } = req.body || {};
		if (!userId) return res.status(401).json({ message: "Unauthorized" });
		if (!totpCode) return res.status(400).json({ message: "Missing TOTP code" });
 
		const user = await User.findById(userId).select(
			"twoFactorEnabled encryptedTwoFactorSecret",
		);
		if (!user) return res.status(404).json({ message: "User not found" });
		if (!user.twoFactorEnabled) {
			return res.status(400).json({ message: "2FA is not enabled" });
		}
 
		const serverPriv = getServerRsaPrivateKey();
		const secretHex = rsa.chunkDecrypt(
			JSON.parse(user.encryptedTwoFactorSecret), serverPriv,
		);
		if (!verifyTotp(totpCode, secretHex)) {
			return res.status(401).json({ message: "Invalid authentication code" });
		}
 
		user.twoFactorEnabled = false;
		user.encryptedTwoFactorSecret = null;
		await user.save();
		return res.status(200).json({ message: "Two-factor authentication disabled" });
	} catch (error) {
		return res.status(500).json({ message: "2FA disable failed" });
	}
}
 
// ─────────────────────────────────────────────────────────────────────────────
// REMAINING ENDPOINTS (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
 
export async function refresh(req, res) {
	try {
		const bodyToken = req.body?.refreshToken || null;
		const cookieToken = getCookieToken(req.headers.cookie, REFRESH_TOKEN_COOKIE);
		const refreshToken = bodyToken || cookieToken;
		if (!refreshToken) {
			clearAccessTokenCookie(res);
			clearRefreshTokenCookie(res);
			return res.status(400).json({ message: "Missing refresh token" });
		}
		const tokenHash = hashToken(refreshToken);
		const user = await User.findOne({ refreshTokenHash: tokenHash, isActive: true });
		if (!user) return res.status(401).json({ message: "Invalid refresh token" });
 
		const accessToken = signJwt(
			{ userId: user._id.toString(), role: user.role, tokenVersion: user.tokenVersion || 0 },
			requireEnv("JWT_SECRET"), 15 * 60,
		);
		const newRefreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(newRefreshToken);
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, newRefreshToken);
		return res.status(200).json({ message: "Refreshed", accessToken });
	} catch (error) {
		return res.status(500).json({ message: "Refresh failed" });
	}
}
 
export async function logout(req, res) {
	try {
		const bodyToken = req.body?.refreshToken || null;
		const cookieToken = getCookieToken(req.headers.cookie, REFRESH_TOKEN_COOKIE);
		const refreshToken = bodyToken || cookieToken;
		if (!refreshToken) return res.status(400).json({ message: "Missing refresh token" });
 
		const tokenHash = hashToken(refreshToken);
		const user = await User.findOne({ refreshTokenHash: tokenHash });
		if (!user) return res.status(200).json({ message: "Logged out" });
 
		user.refreshTokenHash = null;
		await user.save();
		clearAccessTokenCookie(res);
		clearRefreshTokenCookie(res);
		return res.status(200).json({ message: "Logged out" });
	} catch (error) {
		return res.status(500).json({ message: "Logout failed" });
	}
}
 
export async function me(req, res) {
	return res.status(200).json({ user: req.user || null });
}
 
export async function changePassword(req, res) {
	try {
		const { currentPassword, newPassword } = req.body || {};
		const err = validatePasswordChangeInput({ currentPassword, newPassword });
		if (err) return res.status(400).json({ message: err });
 
		const userId = req.user?.id;
		if (!userId) return res.status(401).json({ message: "Unauthorized" });
 
		const user = await User.findById(userId);
		if (!user || !user.isActive) return res.status(401).json({ message: "User inactive" });
 
		const ok = verifyPassword(currentPassword, user.passwordSalt, user.passwordHash);
		if (!ok) return res.status(401).json({ message: "Invalid credentials" });
 
		const salt = generateSalt();
		const passwordHash = hashPassword(newPassword, salt);
		user.passwordSalt = salt;
		user.passwordHash = passwordHash;
		user.tokenVersion = (user.tokenVersion || 0) + 1;
		user.refreshTokenHash = null;
		await user.save();
		clearAccessTokenCookie(res);
		clearRefreshTokenCookie(res);
		return res.status(200).json({ message: "Password updated" });
	} catch (error) {
		return res.status(500).json({ message: "Password update failed" });
	}
}
 
export async function session(req, res) {
	const user = req.user || null;
	if (!user) return res.status(401).json({ message: "Unauthorized" });
	return res.status(200).json({ userId: user.id, role: user.role });
}
 
export async function keys(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) return res.status(401).json({ message: "Unauthorized" });
 
		const user = await User.findById(userId).select("encryptedPrivateKey encryptedEccPrivateKey");
		if (!user) return res.status(404).json({ message: "User not found" });
 
		const serverPriv = getServerRsaPrivateKey();
		const rsaPrivateKey = rsa.chunkDecrypt(JSON.parse(user.encryptedPrivateKey), serverPriv);
		const eccPrivateKey = user.encryptedEccPrivateKey
			? rsa.chunkDecrypt(JSON.parse(user.encryptedEccPrivateKey), serverPriv)
			: null;
 
		return res.status(200).json({ userId, rsaPrivateKey, eccPrivateKey });
	} catch (error) {
		return res.status(500).json({ message: "Failed to load keys" });
	}
}
 
export default {
	register, login, verify2FA, setup2FA, confirm2FA, disable2FA,
	refresh, logout, me, changePassword, session, keys,
};