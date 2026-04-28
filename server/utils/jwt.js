/**
 * utils/jwt.js
 * Minimal JWT (HS256) implementation using custom HMAC-SHA256.
 */

import { hmacSha256 } from "../crpyto/hmac.js";
import { toBase64 } from "../crpyto/utils.js";

function base64UrlEncodeBytes(bytes) {
	return toBase64(bytes)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function base64UrlEncodeJson(obj) {
	const json = JSON.stringify(obj);
	return base64UrlEncodeBytes(new TextEncoder().encode(json));
}

function base64UrlDecodeToString(b64url) {
	const padded =
		b64url.replace(/-/g, "+").replace(/_/g, "/") +
		"===".slice((b64url.length + 3) % 4);
	return Buffer.from(padded, "base64").toString("utf8");
}

export function signJwt(payload, secret, expiresInSeconds) {
	const header = { alg: "HS256", typ: "JWT" };
	const now = Math.floor(Date.now() / 1000);
	const body = { ...payload, iat: now, exp: now + expiresInSeconds };

	const encodedHeader = base64UrlEncodeJson(header);
	const encodedBody = base64UrlEncodeJson(body);
	const signingInput = `${encodedHeader}.${encodedBody}`;

	const signatureBytes = hmacSha256(secret, signingInput);
	const signature = base64UrlEncodeBytes(signatureBytes);

	return `${signingInput}.${signature}`;
}

export function verifyJwt(token, secret) {
	if (!token || typeof token !== "string")
		return { valid: false, payload: null };
	const parts = token.split(".");
	if (parts.length !== 3) return { valid: false, payload: null };

	const [encodedHeader, encodedBody, signature] = parts;
	const signingInput = `${encodedHeader}.${encodedBody}`;
	const expected = base64UrlEncodeBytes(hmacSha256(secret, signingInput));
	if (expected !== signature) return { valid: false, payload: null };

	try {
		const payload = JSON.parse(base64UrlDecodeToString(encodedBody));
		const now = Math.floor(Date.now() / 1000);
		if (typeof payload.exp === "number" && payload.exp < now) {
			return { valid: false, payload: null };
		}
		return { valid: true, payload };
	} catch {
		return { valid: false, payload: null };
	}
}

export default { signJwt, verifyJwt };
