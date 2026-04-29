/**
 * crypto/hmac.js
 *
 * SHA-256 and HMAC-SHA256 implemented entirely from scratch.
 * No Node crypto module. No external packages.
 * Uses only: Uint8Array, DataView, and pure arithmetic.
 *
 * Exports:
 *   sha256(input)                        → Uint8Array (32 bytes)
 *   sha256Hex(input)                     → hex string
 *   hmacSha256(key, message)             → Uint8Array (32 bytes)
 *   hmacSha256Hex(key, message)          → hex string
 *   sign(fields, serverKey)              → hex string  (for document MACs)
 *   verify(fields, serverKey, stored)    → boolean
 */

import { stringToBytes, toHex, fromHex, concatBytes } from "./utils.js";

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 Constants
// ─────────────────────────────────────────────────────────────────────────────

// First 32 bits of the fractional parts of the cube roots of the first 64 primes
const K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// Initial hash values: first 32 bits of fractional parts of square roots of first 8 primes
const H0 = new Uint32Array([
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19,
]);

// ─────────────────────────────────────────────────────────────────────────────
// Bit operations (32-bit)
// ─────────────────────────────────────────────────────────────────────────────

/** Right rotate a 32-bit integer by n bits */
const rotr32 = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

/** 32-bit addition with overflow wrapping */
const add32 = (...args) => args.reduce((a, b) => (a + b) >>> 0);

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 Core
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Pad a message per SHA-256 spec:
 *   1. Append bit 1 (0x80 byte)
 *   2. Append 0 bytes until length ≡ 56 mod 64
 *   3. Append original message bit-length as 64-bit big-endian integer
 */
function sha256Pad(msgBytes) {
	const msgLen = msgBytes.length;
	const bitLen = msgLen * 8;

	// Number of zero bytes needed: ensure total ≡ 56 mod 64 after the 0x80 byte
	const zeroPad = (((55 - msgLen) % 64) + 64) % 64;
	const padded = new Uint8Array(msgLen + 1 + zeroPad + 8);
	padded.set(msgBytes);
	padded[msgLen] = 0x80;

	// Write 64-bit big-endian bit length
	const view = new DataView(padded.buffer);
	// High 32 bits: use Math.floor with 2**32 correctly handled via BigInt-free
	// integer division. For any realistic message (< 2^32 bits = 512 MB) this
	// is 0; written explicitly for spec compliance.
	view.setUint32(padded.length - 8, (bitLen / 2 ** 32) >>> 0, false);
	// Low 32 bits
	view.setUint32(padded.length - 4, bitLen >>> 0, false);

	return padded;
}

/**
 * Process a single 512-bit (64-byte) block.
 * Mutates the `hash` Uint32Array in place.
 */
function processBlock(block, hash) {
	const W = new Uint32Array(64);
	const view = new DataView(block.buffer, block.byteOffset, 64);

	// Prepare message schedule
	for (let t = 0; t < 16; t++) {
		W[t] = view.getUint32(t * 4, false); // big-endian
	}
	for (let t = 16; t < 64; t++) {
		const s0 = rotr32(W[t - 15], 7) ^ rotr32(W[t - 15], 18) ^ (W[t - 15] >>> 3);
		const s1 = rotr32(W[t - 2], 17) ^ rotr32(W[t - 2], 19) ^ (W[t - 2] >>> 10);
		W[t] = add32(W[t - 16], s0, W[t - 7], s1);
	}

	// Working variables
	let [a, b, c, d, e, f, g, h] = hash;

	// 64 rounds
	for (let t = 0; t < 64; t++) {
		const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		const ch = (e & f) ^ (~e & g);
		const temp1 = add32(h, S1, ch, K[t], W[t]);
		const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		const maj = (a & b) ^ (a & c) ^ (b & c);
		const temp2 = add32(S0, maj);

		h = g;
		g = f;
		f = e;
		e = add32(d, temp1);
		d = c;
		c = b;
		b = a;
		a = add32(temp1, temp2);
	}

	// Add compressed chunk to current hash value
	hash[0] = add32(hash[0], a);
	hash[1] = add32(hash[1], b);
	hash[2] = add32(hash[2], c);
	hash[3] = add32(hash[3], d);
	hash[4] = add32(hash[4], e);
	hash[5] = add32(hash[5], f);
	hash[6] = add32(hash[6], g);
	hash[7] = add32(hash[7], h);
}

/**
 * Compute SHA-256 of input.
 * @param {Uint8Array|string} input
 * @returns {Uint8Array} 32-byte digest
 */
export function sha256(input) {
	const msgBytes = typeof input === "string" ? stringToBytes(input) : input;
	const padded = sha256Pad(msgBytes);
	const hash = new Uint32Array(H0); // copy initial values — H0 is never mutated

	// Process each 64-byte block
	for (let i = 0; i < padded.length; i += 64) {
		processBlock(padded.subarray(i, i + 64), hash);
	}

	// Produce final 32-byte digest (big-endian)
	const digest = new Uint8Array(32);
	const dv = new DataView(digest.buffer);
	for (let i = 0; i < 8; i++) {
		dv.setUint32(i * 4, hash[i], false);
	}
	return digest;
}

/**
 * SHA-256 returning a lowercase hex string.
 * @param {Uint8Array|string} input
 * @returns {string}
 */
export function sha256Hex(input) {
	return toHex(sha256(input));
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256
// ─────────────────────────────────────────────────────────────────────────────

/**
 * HMAC-SHA256 per RFC 2104.
 *
 *   ipad = 0x36 repeated to block size
 *   opad = 0x5c repeated to block size
 *   HMAC = SHA256( (key XOR opad) || SHA256( (key XOR ipad) || message ) )
 *
 * @param {Uint8Array|string} key
 * @param {Uint8Array|string} message
 * @returns {Uint8Array} 32-byte MAC
 */
export function hmacSha256(key, message) {
	const BLOCK_SIZE = 64; // SHA-256 block size in bytes

	let keyBytes = typeof key === "string" ? stringToBytes(key) : key;
	const msgBytes =
		typeof message === "string" ? stringToBytes(message) : message;

	// If key is longer than block size, hash it first
	if (keyBytes.length > BLOCK_SIZE) {
		keyBytes = sha256(keyBytes);
	}

	// Pad key to block size with zeros
	const paddedKey = new Uint8Array(BLOCK_SIZE);
	paddedKey.set(keyBytes);

	// Create ipad and opad
	const ipad = new Uint8Array(BLOCK_SIZE);
	const opad = new Uint8Array(BLOCK_SIZE);
	for (let i = 0; i < BLOCK_SIZE; i++) {
		ipad[i] = paddedKey[i] ^ 0x36;
		opad[i] = paddedKey[i] ^ 0x5c;
	}

	// Inner hash: SHA256(ipad || message)
	const innerHash = sha256(concatBytes(ipad, msgBytes));

	// Outer hash: SHA256(opad || innerHash)
	return sha256(concatBytes(opad, innerHash));
}

/**
 * HMAC-SHA256 returning a lowercase hex string.
 * @param {Uint8Array|string} key
 * @param {Uint8Array|string} message
 * @returns {string}
 */
export function hmacSha256Hex(key, message) {
	return toHex(hmacSha256(key, message));
}

// ─────────────────────────────────────────────────────────────────────────────
// Document MAC helpers (used by all models)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute a MAC signature over an ordered list of field values.
 * All values are coerced to strings, joined with a null byte separator
 * (prevents field concatenation collisions), then HMAC'd.
 *
 * Usage:
 *   const sig = sign(
 *     [doc.encryptedUsername, doc.encryptedEmail, doc.encryptedContact],
 *     process.env.HMAC_SERVER_KEY
 *   );
 *
 * @param {Array<string|number|null|undefined>} fields
 * @param {string} serverKey  hex string from env
 * @returns {string} hex MAC
 */
export function sign(fields, serverKey) {
	const message = fields.map((f) => (f == null ? "" : String(f))).join("\x00");
	const keyBytes = fromHex(serverKey);
	return hmacSha256Hex(keyBytes, message);
}

/**
 * Verify a MAC signature. Returns true if valid, false otherwise.
 *
 * Constant-time comparison is performed over the raw digest bytes (not hex
 * strings) to eliminate any hypothetical timing difference from hex encoding.
 *
 * BUG FIX: the original compared hex strings character-by-character.
 * While functionally correct (hex output is always 64 chars), comparing at
 * the byte level is the conventional, auditor-friendly approach and removes
 * any dependency on the hex-encoding step being constant-time.
 *
 * @param {Array<string|number|null|undefined>} fields
 * @param {string} serverKey  hex string from env
 * @param {string} storedSignature  hex MAC stored in the document
 * @returns {boolean}
 */
export function verify(fields, serverKey, storedSignature) {
	// Compute expected MAC as raw bytes
	const message = fields.map((f) => (f == null ? "" : String(f))).join("\x00");
	const keyBytes = fromHex(serverKey);
	const expected = hmacSha256(keyBytes, message); // Uint8Array, always 32 bytes

	// Decode storedSignature from hex to bytes for byte-level comparison
	let stored;
	try {
		stored = fromHex(storedSignature);
	} catch {
		return false; // BUG FIX: invalid hex in storedSignature must not throw —
		// it must return false. The original code would propagate the
		// exception from fromHex() up to the caller, turning an
		// authentication failure into an unhandled crash.
	}

	// HMAC-SHA256 output is always 32 bytes; a stored value of any other
	// length is definitively invalid.
	if (expected.length !== stored.length) return false;

	// Constant-time byte comparison: visit every byte even after a mismatch
	let diff = 0;
	for (let i = 0; i < expected.length; i++) {
		diff |= expected[i] ^ stored[i];
	}
	return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-export for convenience
// ─────────────────────────────────────────────────────────────────────────────

export default { sha256, sha256Hex, hmacSha256, hmacSha256Hex, sign, verify };
