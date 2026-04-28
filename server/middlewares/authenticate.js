/**
 * middlewares/authenticate.js
 * Verifies JWT and attaches req.user.
 */

import { User } from "../models/index.js";
import { verifyJwt } from "../utils/jwt.js";

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
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

export default async function authenticate(req, res, next) {
	try {
		const authHeader = req.headers.authorization || "";
		const headerToken = authHeader.startsWith("Bearer ")
			? authHeader.slice(7)
			: null;
		const cookieToken = getCookieToken(req.headers.cookie, "accessToken");
		const token = headerToken || cookieToken;

		if (!token) {
			return res.status(401).json({ message: "Missing token" });
		}

		const { valid, payload } = verifyJwt(token, requireEnv("JWT_SECRET"));
		if (!valid || !payload?.userId) {
			return res.status(401).json({ message: "Invalid token" });
		}

		const user = await User.findById(payload.userId).select(
			"role tokenVersion keyVersion isActive",
		);
		if (!user || !user.isActive) {
			return res.status(401).json({ message: "User inactive" });
		}

		const tokenVersion = payload.tokenVersion || 0;
		if ((user.tokenVersion || 0) !== tokenVersion) {
			return res.status(401).json({ message: "Token revoked" });
		}

		req.user = {
			id: user._id.toString(),
			role: user.role,
			keyVersion: user.keyVersion || 1,
			tokenVersion: user.tokenVersion || 0,
		};
		return next();
	} catch (error) {
		return res.status(500).json({ message: "Auth failed" });
	}
}
