/**
 * crypto/hash.js
 *
 * Custom password hashing — PBKDF2-like key stretching using our own SHA-256.
 * No bcrypt, no crypto.pbkdf2, no external packages.
 *
 * Algorithm:
 *   1. Generate a 32-byte random salt (hex string)
 *   2. Iteratively hash: hash_i = SHA256(hash_{i-1} || salt || iteration_counter)
 *      for 100,000 iterations (key stretching to resist brute force)
 *   3. Return the final 32-byte digest as a hex string
 *
 * Exports:
 *   generateSalt()                              → hex string (64 chars)
 *   hashPassword(password, salt)                → hex string (64 chars)
 *   verifyPassword(input, salt, storedHash)     → boolean
 *   hashField(value)                            → hex string  (for emailHash, usernameHash)
 */

import { sha256, hmacSha256Hex } from "./hmac.js";
import {
	randomBytes,
	toHex,
	fromHex,
	stringToBytes,
	concatBytes,
	constantTimeEqual,
} from "./utils.js";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** Number of hash iterations — high enough to be slow for attackers */
const ITERATIONS = 100_000;

/** Salt length in bytes */
const SALT_BYTES = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Salt generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random salt.
 * Uses crypto.getRandomValues (entropy, not encryption — allowed per project rules).
 *
 * @returns {string} 64-character hex string
 */
export function generateSalt() {
	return toHex(randomBytes(SALT_BYTES));
}

// ─────────────────────────────────────────────────────────────────────────────
// Password hashing
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hash a password with PBKDF2-like key stretching.
 *
 * Process:
 *   input_0 = UTF8(password) || fromHex(salt)
 *   hash_0  = SHA256(input_0)
 *   hash_i  = SHA256(hash_{i-1} || fromHex(salt) || i2bytes(i))
 *   ...repeat ITERATIONS times...
 *   return toHex(hash_N)
 *
 * Including the iteration counter in each round prevents a
 * "rainbow chain" shortcut where an attacker could reuse intermediate hashes.
 *
 * @param {string} password  plaintext password from user
 * @param {string} salt      hex string from generateSalt()
 * @returns {string}         64-character hex string
 */
export function hashPassword(password, salt) {
	const saltBytes = fromHex(salt);
	const passwordBytes = stringToBytes(password);

	// Initial hash: SHA256(password || salt)
	let current = sha256(concatBytes(passwordBytes, saltBytes));

	// Iterative stretching
	for (let i = 1; i < ITERATIONS; i++) {
		// Encode iteration counter as 4-byte big-endian to include in each round
		const counter = new Uint8Array(4);
		const view = new DataView(counter.buffer);
		view.setUint32(0, i, false); // big-endian

		// hash_i = SHA256(hash_{i-1} || salt || counter)
		current = sha256(concatBytes(current, saltBytes, counter));
	}

	return toHex(current);
}

// ─────────────────────────────────────────────────────────────────────────────
// Password verification
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a password against a stored hash.
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param {string} inputPassword  plaintext password to check
 * @param {string} salt           hex salt stored in User document
 * @param {string} storedHash     hex hash stored in User document
 * @returns {boolean}
 */
export function verifyPassword(inputPassword, salt, storedHash) {
	const computed = hashPassword(inputPassword, salt);
	// Constant-time hex string comparison
	const computedBytes = fromHex(computed);
	const storedBytes = fromHex(storedHash);
	return constantTimeEqual(computedBytes, storedBytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// Field hashing (for lookup indexes — not password hashing)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hash a plaintext field value for use as a database lookup key.
 * Used for: emailHash, usernameHash — allows uniqueness checks and
 * login lookups without decrypting the entire collection.
 *
 * This uses HMAC-SHA256 with a server secret (pepper) to prevent
 * an attacker who steals the database from reversing hashes via
 * rainbow tables or brute force without also having the server secret.
 *
 * @param {string} value        e.g. "user@example.com"
 * @param {string} serverKey    hex HMAC key from env (HMAC_SERVER_KEY)
 * @returns {string}            64-character hex string
 */
export function hashField(value, serverKey) {
	return hmacSha256Hex(fromHex(serverKey), value.toLowerCase().trim());
}

// ─────────────────────────────────────────────────────────────────────────────
// Refresh token hashing
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hash a refresh token before storing it.
 * We store SHA256(token) not the token itself — so even if the DB is
 * compromised, the tokens cannot be replayed without the original value.
 *
 * @param {string} token  hex refresh token
 * @returns {string}      hex hash
 */
export function hashToken(token) {
	return toHex(sha256(stringToBytes(token)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
	generateSalt,
	hashPassword,
	verifyPassword,
	hashField,
	hashToken,
};
