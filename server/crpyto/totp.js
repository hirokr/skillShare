/**
 * crypto/totp.js
 *
 * TOTP (Time-based One-Time Password) — RFC 6238 / RFC 4226
 * Implemented from scratch using our own HMAC-SHA256 primitives.
 * No otplib, no speakeasy, no external packages.
 *
 * Algorithm (HOTP base, RFC 4226):
 *   1. counter = floor(unix_time / TIME_STEP)
 *   2. HMAC     = HMAC-SHA256(secret_bytes, counter_as_8_bytes_big_endian)
 *   3. offset   = last_nibble(HMAC)
 *   4. truncated = (HMAC[offset..offset+3] & 0x7FFFFFFF) mod 10^DIGITS
 *
 * Note: RFC 4226 specifies HMAC-SHA1, but since we only have SHA-256 from
 * scratch and the project bans importing crypto, we use HMAC-SHA256 here.
 * The verifier and generator both use the same algorithm, so codes match.
 *
 * Exports:
 *   generateSecret()                → hex string (20 bytes)
 *   generateTotp(secretHex, time?)  → 6-digit string
 *   verifyTotp(token, secretHex)    → boolean  (±1 window tolerance)
 *   buildOtpAuthUrl(secret, label)  → otpauth:// URI for QR codes
 */

import { hmacSha256 } from "./hmac.js";
import { randomBytes, toHex, fromHex } from "./utils.js";

/** TOTP time step in seconds (standard is 30) */
const TIME_STEP = 30;

/** Number of OTP digits */
const DIGITS = 6;

/** Acceptance window: ±1 time step to account for clock skew */
const WINDOW = 1;

/**
 * Generate a random TOTP secret.
 * 20 bytes = 160 bits, returned as a hex string.
 * The hex string is stored RSA-encrypted in the User document.
 *
 * @returns {string} 40-character hex string
 */
export function generateSecret() {
	return toHex(randomBytes(20));
}

/**
 * Encode bytes as Base32 (RFC 4648).
 * Required for otpauth:// URIs consumed by authenticator apps.
 *
 * @param {Uint8Array} bytes
 * @returns {string} uppercase Base32 string
 */
function toBase32(bytes) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = 0;
	let value = 0;
	let output = "";

	for (let i = 0; i < bytes.length; i++) {
		value = (value << 8) | bytes[i];
		bits += 8;
		while (bits >= 5) {
			output += alphabet[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}

	if (bits > 0) {
		output += alphabet[(value << (5 - bits)) & 31];
	}

	// Pad to multiple of 8
	while (output.length % 8 !== 0) {
		output += "=";
	}

	return output;
}

/**
 * Compute a single TOTP code for a given counter value.
 *
 * @param {Uint8Array} secretBytes  raw secret bytes
 * @param {number}     counter      TOTP counter (floor(time / TIME_STEP))
 * @returns {string}                zero-padded DIGITS-digit string
 */
function hotp(secretBytes, counter) {
	// Encode counter as 8-byte big-endian (HOTP spec)
	const counterBytes = new Uint8Array(8);
	let c = counter;
	for (let i = 7; i >= 0; i--) {
		counterBytes[i] = c & 0xff;
		c = Math.floor(c / 256);
	}

	// HMAC-SHA256(secret, counter)
	const mac = hmacSha256(secretBytes, counterBytes);

	// Dynamic truncation: use last nibble as offset
	const offset = mac[mac.length - 1] & 0x0f;

	// Extract 4 bytes at offset, mask high bit (per RFC 4226 §5.4)
	const code =
		(((mac[offset] & 0x7f) << 24) |
			((mac[offset + 1] & 0xff) << 16) |
			((mac[offset + 2] & 0xff) << 8) |
			(mac[offset + 3] & 0xff)) %
		10 ** DIGITS;

	return code.toString().padStart(DIGITS, "0");
}

/**
 * Generate the current TOTP code for a given secret.
 *
 * @param {string} secretHex   hex string (from generateSecret())
 * @param {number} [nowMs]     optional timestamp in ms (defaults to Date.now())
 * @returns {string}           6-digit TOTP code
 */
export function generateTotp(secretHex, nowMs = Date.now()) {
	const secretBytes = fromHex(secretHex);
	const counter = Math.floor(nowMs / 1000 / TIME_STEP);
	return hotp(secretBytes, counter);
}

/**
 * Verify a TOTP token against a secret, accepting a ±WINDOW step tolerance
 * to handle clock skew between client and server.
 *
 * @param {string} token      6-digit string from authenticator app
 * @param {string} secretHex  hex string stored in User document (decrypted)
 * @returns {boolean}
 */
export function verifyTotp(token, secretHex) {
	if (!token || typeof token !== "string") return false;
	const cleaned = token.replace(/\s/g, "");
	if (!/^\d{6}$/.test(cleaned)) return false;

	const secretBytes = fromHex(secretHex);
	const counter = Math.floor(Date.now() / 1000 / TIME_STEP);

	for (let delta = -WINDOW; delta <= WINDOW; delta++) {
		const expected = hotp(secretBytes, counter + delta);
		if (expected === cleaned) return true;
	}

	return false;
}

/**
 * Build an otpauth:// URI for use with QR code generators.
 * Compatible with Google Authenticator, Authy, etc.
 *
 * @param {string} secretHex  hex secret
 * @param {string} label      e.g. "user@example.com"
 * @param {string} [issuer]   e.g. "SkillShare"
 * @returns {string}          otpauth://totp/... URI
 */
export function buildOtpAuthUrl(secretHex, label, issuer = "SkillShare") {
	const secretBase32 = toBase32(fromHex(secretHex));
	const encodedLabel = encodeURIComponent(label);
	const encodedIssuer = encodeURIComponent(issuer);
	return (
		`otpauth://totp/${encodedLabel}` +
		`?secret=${secretBase32}` +
		`&issuer=${encodedIssuer}` +
		`&algorithm=SHA256` +
		`&digits=${DIGITS}` +
		`&period=${TIME_STEP}`
	);
}

export default {
	generateSecret,
	generateTotp,
	verifyTotp,
	buildOtpAuthUrl,
};