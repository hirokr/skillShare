/**
 * controllers/authController.js
 * User authentication: register, login, refresh, logout (no 2FA).
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
import { signJwt } from "../utils/jwt.js";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ACCESS_TOKEN_COOKIE = "accessToken";
const REFRESH_TOKEN_COOKIE = "refreshToken";

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
	if (!username || !email || !password) {
		return "Missing required fields";
	}
	if (!EMAIL_REGEX.test(email)) {
		return "Invalid email format";
	}
	if (password.length < 8 || password.length > 128) {
		return "Password must be 8-128 characters";
	}
	const strengthError = passwordStrengthError(password);
	if (strengthError) {
		return strengthError;
	}
	if (username.length < 3 || username.length > 32) {
		return "Username must be 3-32 characters";
	}
	if (contact && contact.length > 64) {
		return "Contact is too long";
	}
	return null;
}

function validateLoginInput({ email, password }) {
	if (!email || !password) {
		return "Missing email or password";
	}
	if (!EMAIL_REGEX.test(email)) {
		return "Invalid email format";
	}
	if (password.length < 8 || password.length > 128) {
		return "Invalid password length";
	}
	return null;
}

function validatePasswordChangeInput({ currentPassword, newPassword }) {
	if (!currentPassword || !newPassword) {
		return "Missing password fields";
	}
	if (newPassword.length < 8 || newPassword.length > 128) {
		return "Password must be 8-128 characters";
	}
	const strengthError = passwordStrengthError(newPassword);
	if (strengthError) {
		return strengthError;
	}
	return null;
}

function getCookieOptions() {
	const isProd = process.env.NODE_ENV === "production";
	return {
		httpOnly: true,
		secure: isProd,
		sameSite: "strict",
		path: "/",
	};
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
	const parts = cookieHeader.split(";");
	for (const part of parts) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) {
			return rest.join("=") || null;
		}
	}
	return null;
}

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function getServerRsaPublicKey() {
	const serialized = requireEnv("SERVER_RSA_PUBLIC_KEY");
	const pub = rsa.deserializePublicKey(serialized);
	return pub;
}

function getServerRsaPrivateKey() {
	const serialized = requireEnv("SERVER_RSA_PRIVATE_KEY");
	return rsa.deserializePrivateKey(serialized);
}

function getServerEccPublicKey() {
	const serialized = requireEnv("SERVER_ECC_PUBLIC_KEY");
	const pub = ecc.deserializePublicKey(serialized);
	return pub;
}

function generateRefreshToken() {
	return toHex(randomBytes(32));
}

export async function register(req, res) {
	try {
		const { username, email, password, contact } = req.body || {};
		const validationError = validateRegisterInput({
			username,
			email,
			password,
			contact,
		});
		if (validationError) {
			return res.status(400).json({ message: validationError });
		}

		const cleanUsername = username.trim();
		const cleanEmail = email.trim().toLowerCase();
		const cleanContact = contact ? contact.trim() : "12390123";

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const usernameHash = hashField(cleanUsername, hmacKey);
		const emailHash = hashField(cleanEmail, hmacKey);

		const existing = await User.findOne({
			$or: [{ usernameHash }, { emailHash }],
		});
		if (existing) {
			return res.status(409).json({ message: "User already exists" });
		}

		// First registered user becomes admin.
		const existingUserCount = await User.countDocuments();
		const role = existingUserCount === 0 ? "admin" : "user";

		const salt = generateSalt();
		const passwordHash = hashPassword(password, salt);

		const serverRsaPub = getServerRsaPublicKey();

		const serverEccPub = getServerEccPublicKey();

		const { publicKey: userRsaPub, privateKey: userRsaPriv } =
			rsa.generateKeyPair();
		const { publicKey: userEccPub, privateKey: userEccPriv } =
			ecc.generateKeyPair();

		const encryptedUsername = ecc.encrypt(cleanUsername, serverEccPub);
		const encryptedEmail = ecc.encrypt(cleanEmail, serverEccPub);
		const encryptedContact = cleanContact
			? ecc.encrypt(cleanContact, serverEccPub)
			: null;

		const serializedRsaPub = rsa.serializePublicKey(userRsaPub);
		const serializedRsaPriv = rsa.serializePrivateKey(userRsaPriv);
		const serializedEccPub = ecc.serializePublicKey(userEccPub);
		const serializedEccPriv = ecc.serializePrivateKey(userEccPriv);

		// FIX 2: a serialised RSA-2048 private key is ~1 100 bytes — far above
		// MAX_CHUNK_BYTES (190).  rsa.encrypt() would throw "OAEP: message too
		// long".  Use chunkEncrypt() instead and JSON-stringify the chunk array
		// for database storage.  The ECC private key is smaller but also
		// exceeds one block, so apply the same treatment for consistency.
		const encryptedPrivateKey = JSON.stringify(
			rsa.chunkEncrypt(serializedRsaPriv, serverRsaPub),
		);
		const encryptedEccPrivateKey = JSON.stringify(
			rsa.chunkEncrypt(serializedEccPriv, serverRsaPub),
		);

		const hmacSignature = signMac(
			[encryptedUsername, encryptedEmail, encryptedContact],
			hmacKey,
		);
		console.log("DONE");

		const user = await User.create({
			encryptedUsername,
			encryptedEmail,
			encryptedContact,
			usernameHash,
			emailHash,
			passwordHash,
			passwordSalt: salt,
			publicKey: serializedRsaPub,
			encryptedPrivateKey,
			eccPublicKey: serializedEccPub,
			encryptedEccPrivateKey,
			hmacSignature,
			role,
		});

		const profileMac = signMac(
			[null, null, null, null, user._id.toString()],
			hmacKey,
		);
		await Profile.create({
			user: user._id,
			hmacSignature: profileMac,
		});

		const keyStoreRsaMac = signMac(
			[serializedRsaPub, encryptedPrivateKey, user._id.toString(), 1, "RSA"],
			hmacKey,
		);
		await KeyStore.create({
			user: user._id,
			algorithm: "RSA",
			version: 1,
			publicKey: serializedRsaPub,
			encryptedPrivateKey,
			keySize: 2048,
			hmacSignature: keyStoreRsaMac,
		});

		const keyStoreEccMac = signMac(
			[serializedEccPub, encryptedEccPrivateKey, user._id.toString(), 1, "ECC"],
			hmacKey,
		);
		await KeyStore.create({
			user: user._id,
			algorithm: "ECC",
			version: 1,
			publicKey: serializedEccPub,
			encryptedPrivateKey: encryptedEccPrivateKey,
			keySize: 256,
			curve: "secp256k1",
			hmacSignature: keyStoreEccMac,
		});

		const accessToken = signJwt(
			{ userId: user._id.toString(), role: user.role, tokenVersion: 0 },
			requireEnv("JWT_SECRET"),
			15 * 60,
		);
		const refreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(refreshToken);
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, refreshToken);

		return res.status(201).json({
			message: "Registered",
			accessToken,
			userId: user._id,
		});
	} catch (error) {
		return res.status(500).json({ message: "Registration failed" });
	}
}

export async function login(req, res) {
	try {
		const { email, password } = req.body || {};
		const validationError = validateLoginInput({ email, password });
		if (validationError) {
			return res.status(400).json({ message: validationError });
		}

		const cleanEmail = email.trim().toLowerCase();

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const emailHash = hashField(cleanEmail, hmacKey);
		const user = await User.findOne({ emailHash, isActive: true });
		if (!user) {
			return res.status(401).json({ message: "Invalid credentials" });
		}

		const ok = verifyPassword(password, user.passwordSalt, user.passwordHash);
		if (!ok) {
			return res.status(401).json({ message: "Invalid credentials" });
		}

		const accessToken = signJwt(
			{
				userId: user._id.toString(),
				role: user.role,
				tokenVersion: user.tokenVersion || 0,
			},
			requireEnv("JWT_SECRET"),
			15 * 60,
		);
		const refreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(refreshToken);
		user.lastLoginAt = new Date();
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, refreshToken);

		return res.status(200).json({
			message: "Logged in",
			accessToken,
			userId: user._id,
		});
	} catch (error) {
		return res.status(500).json({ message: "Login failed" });
	}
}

export async function refresh(req, res) {
	try {
		const bodyToken = req.body?.refreshToken || null;
		const cookieToken = getCookieToken(
			req.headers.cookie,
			REFRESH_TOKEN_COOKIE,
		);
		const refreshToken = bodyToken || cookieToken;
		if (!refreshToken) {
			clearAccessTokenCookie(res);
			clearRefreshTokenCookie(res);
			return res.status(400).json({ message: "Missing refresh token" });
		}

		const tokenHash = hashToken(refreshToken);
		const user = await User.findOne({
			refreshTokenHash: tokenHash,
			isActive: true,
		});
		if (!user) {
			return res.status(401).json({ message: "Invalid refresh token" });
		}

		const accessToken = signJwt(
			{
				userId: user._id.toString(),
				role: user.role,
				tokenVersion: user.tokenVersion || 0,
			},
			requireEnv("JWT_SECRET"),
			15 * 60,
		);
		const newRefreshToken = generateRefreshToken();
		user.refreshTokenHash = hashToken(newRefreshToken);
		await user.save();
		setAccessTokenCookie(res, accessToken);
		setRefreshTokenCookie(res, newRefreshToken);

		return res.status(200).json({
			message: "Refreshed",
			accessToken,
		});
	} catch (error) {
		return res.status(500).json({ message: "Refresh failed" });
	}
}

export async function logout(req, res) {
	try {
		const bodyToken = req.body?.refreshToken || null;
		const cookieToken = getCookieToken(
			req.headers.cookie,
			REFRESH_TOKEN_COOKIE,
		);
		const refreshToken = bodyToken || cookieToken;
		if (!refreshToken) {
			return res.status(400).json({ message: "Missing refresh token" });
		}

		const tokenHash = hashToken(refreshToken);
		const user = await User.findOne({ refreshTokenHash: tokenHash });
		if (!user) {
			return res.status(200).json({ message: "Logged out" });
		}

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
		const validationError = validatePasswordChangeInput({
			currentPassword,
			newPassword,
		});
		if (validationError) {
			return res.status(400).json({ message: validationError });
		}

		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const user = await User.findById(userId);
		if (!user || !user.isActive) {
			return res.status(401).json({ message: "User inactive" });
		}

		const ok = verifyPassword(
			currentPassword,
			user.passwordSalt,
			user.passwordHash,
		);
		if (!ok) {
			return res.status(401).json({ message: "Invalid credentials" });
		}

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
	if (!user) {
		return res.status(401).json({ message: "Unauthorized" });
	}
	return res.status(200).json({ userId: user.id, role: user.role });
}

export async function keys(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const user = await User.findById(userId).select(
			"encryptedPrivateKey encryptedEccPrivateKey",
		);
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}

		const serverPriv = getServerRsaPrivateKey();

		// FIX 3: private keys were stored via chunkEncrypt (JSON array string),
		// so they must be retrieved with chunkDecrypt.  Using rsa.decrypt()
		// (single-block) here would throw or return garbage.
		const rsaPrivateKey = rsa.chunkDecrypt(
			JSON.parse(user.encryptedPrivateKey),
			serverPriv,
		);
		const eccPrivateKey = user.encryptedEccPrivateKey
			? rsa.chunkDecrypt(JSON.parse(user.encryptedEccPrivateKey), serverPriv)
			: null;

		return res.status(200).json({
			userId,
			rsaPrivateKey,
			eccPrivateKey,
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to load keys" });
	}
}

export default {
	register,
	login,
	refresh,
	logout,
	me,
	changePassword,
	session,
	keys,
};
