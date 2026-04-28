/**
 * crypto/utils.js
 *
 * Shared low-level helpers used by rsa.js, ecc.js, hmac.js, and hash.js.
 * No external dependencies. Uses only:
 *   - crypto.getRandomValues  (entropy only — NOT encryption)
 *   - TextEncoder / TextDecoder (Web API, available in Node 18+)
 *   - Buffer (Node built-in, for base64 I/O only)
 */

import { webcrypto } from "crypto"; // Node 18 built-in — used for getRandomValues ONLY
// Must be called as webcrypto.getRandomValues (not destructured) to preserve `this` binding
const getRandomValues = (buf) => webcrypto.getRandomValues(buf);

// ─────────────────────────────────────────────────────────────────────────────
// String ↔ Bytes
// ─────────────────────────────────────────────────────────────────────────────

/** Encode a UTF-8 string to a Uint8Array */
export function stringToBytes(str) {
	return new TextEncoder().encode(str);
}

/** Decode a Uint8Array to a UTF-8 string */
export function bytesToString(bytes) {
	return new TextDecoder().decode(bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 ↔ Bytes
// ─────────────────────────────────────────────────────────────────────────────

/** Encode a Uint8Array to a base64 string */
export function toBase64(bytes) {
	return Buffer.from(bytes).toString("base64");
}

/** Decode a base64 string to a Uint8Array */
export function fromBase64(b64) {
	return new Uint8Array(Buffer.from(b64, "base64"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex ↔ Bytes
// ─────────────────────────────────────────────────────────────────────────────

/** Encode a Uint8Array to a lowercase hex string */
export function toHex(bytes) {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Decode a hex string to a Uint8Array */
export function fromHex(hex) {
	if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
	const result = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// BigInt ↔ Bytes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convert a BigInt to a big-endian Uint8Array of exactly `length` bytes.
 * Pads with leading zeros if needed; throws if the number is too large.
 */
export function bigIntToBytes(n, length) {
	if (n < 0n) throw new Error("bigIntToBytes: negative BigInt not supported");
	const hex = n.toString(16).padStart(length * 2, "0");
	if (hex.length > length * 2) {
		throw new Error(
			`bigIntToBytes: BigInt too large for ${length} bytes (needs ${Math.ceil(hex.length / 2)})`,
		);
	}
	return fromHex(hex);
}

/**
 * Convert a big-endian Uint8Array to a BigInt.
 */
export function bytesToBigInt(bytes) {
	return BigInt("0x" + toHex(bytes));
}

// ─────────────────────────────────────────────────────────────────────────────
// Secure random
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate `count` cryptographically random bytes.
 * Uses crypto.getRandomValues — this is an entropy source, not encryption.
 */
export function randomBytes(count) {
	const buf = new Uint8Array(count);
	getRandomValues(buf);
	return buf;
}

/**
 * Generate a random BigInt in the range [min, max) using rejection sampling.
 * Safe against modular bias.
 */
export function randomBigInt(min, max) {
	if (max <= min) throw new Error("randomBigInt: max must be > min");
	const range = max - min;
	const byteLength = Math.ceil(range.toString(16).length / 2);
	// Add extra bytes to reduce bias
	const extraBytes = 8;
	const totalBytes = byteLength + extraBytes;

	while (true) {
		const bytes = randomBytes(totalBytes);
		const candidate = bytesToBigInt(bytes) % range;
		// Rejection sampling: discard values in the biased tail
		const limit =
			2n ** BigInt(totalBytes * 8) - (2n ** BigInt(totalBytes * 8) % range);
		if (bytesToBigInt(bytes) < limit) {
			return min + candidate;
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Modular arithmetic
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Modular exponentiation: base^exp mod mod — using square-and-multiply.
 * All BigInt. This is the core of RSA.
 */
export function modPow(base, exp, mod) {
	if (mod === 1n) return 0n;
	let result = 1n;
	base = base % mod;
	while (exp > 0n) {
		if (exp % 2n === 1n) {
			result = (result * base) % mod;
		}
		exp = exp / 2n;
		base = (base * base) % mod;
	}
	return result;
}

/**
 * Extended Euclidean Algorithm.
 * Returns { gcd, x, y } such that a*x + b*y = gcd(a, b).
 */
export function extendedGcd(a, b) {
	if (b === 0n) return { gcd: a, x: 1n, y: 0n };
	const { gcd, x, y } = extendedGcd(b, a % b);
	return { gcd, x: y, y: x - (a / b) * y };
}

/**
 * Modular inverse of a mod m.
 * Throws if gcd(a, m) !== 1 (no inverse exists).
 */
export function modInverse(a, m) {
	const { gcd, x } = extendedGcd(((a % m) + m) % m, m);
	if (gcd !== 1n) throw new Error("modInverse: no inverse (gcd !== 1)");
	return ((x % m) + m) % m;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant-time byte comparison (prevents timing attacks)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compare two Uint8Arrays in constant time.
 * Returns true only if they are identical in length and content.
 */
export function constantTimeEqual(a, b) {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR bytes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * XOR two Uint8Arrays of equal length. Returns a new Uint8Array.
 */
export function xorBytes(a, b) {
	if (a.length !== b.length)
		throw new Error(`xorBytes: length mismatch (${a.length} vs ${b.length})`);
	const result = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		result[i] = a[i] ^ b[i];
	}
	return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Concat bytes
// ─────────────────────────────────────────────────────────────────────────────

/** Concatenate any number of Uint8Arrays into one. */
export function concatBytes(...arrays) {
	const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const arr of arrays) {
		result.set(arr, offset);
		offset += arr.length;
	}
	return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// i2osp / os2ip (Integer to Octet String, per RFC 8017)
// ─────────────────────────────────────────────────────────────────────────────

/** Integer to Octet String Primitive — BigInt → fixed-length byte array */
export function i2osp(n, length) {
	return bigIntToBytes(n, length);
}

/** Octet String to Integer Primitive — byte array → BigInt */
export function os2ip(bytes) {
	return bytesToBigInt(bytes);
}
