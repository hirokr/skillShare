/**
 * crypto/rsa.js
 *
 * RSA-2048 with OAEP padding — implemented from scratch using BigInt.
 * No Node crypto, no forge, no node-rsa. Pure JavaScript.
 *
 * Implements:
 *   - Miller-Rabin primality testing
 *   - RSA key pair generation (2048-bit)
 *   - OAEP padding (MGF1 with our SHA-256)
 *   - RSA-OAEP encrypt / decrypt
 *   - Chunk encrypt / decrypt for messages longer than one RSA block
 *   - Key serialisation to/from base64 JSON
 *
 * Exports:
 *   generateKeyPair()                          → { publicKey, privateKey }
 *   encrypt(message, publicKey)                → base64 ciphertext
 *   decrypt(ciphertext, privateKey)            → string plaintext
 *   chunkEncrypt(longString, publicKey)        → string[]
 *   chunkDecrypt(chunks, privateKey)           → string
 *   serializePublicKey(publicKey)              → base64 string
 *   deserializePublicKey(base64)               → publicKey object
 *   serializePrivateKey(privateKey)            → base64 string
 *   deserializePrivateKey(base64)              → privateKey object
 */

import { sha256 } from "./hmac.js";
import {
	randomBytes,
	randomBigInt,
	modPow,
	modInverse,
	toBase64,
	fromBase64,
	toHex,
	fromHex,
	bigIntToBytes,
	bytesToBigInt,
	concatBytes,
	i2osp,
	os2ip,
} from "./utils.js";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const KEY_BITS = 2048;
const KEY_BYTES = KEY_BITS / 8; // 256
const E = 65537n; // standard public exponent

// OAEP parameters
const HASH_LEN = 32; // SHA-256 output bytes
// Max plaintext per block: KEY_BYTES - 2*HASH_LEN - 2 = 256 - 64 - 2 = 190
export const MAX_CHUNK_BYTES = KEY_BYTES - 2 * HASH_LEN - 2;
// Safe chunk size for UTF-8 strings (some chars = 3-4 bytes)
export const CHUNK_SIZE = 120; // characters per chunk (conservative)

// ─────────────────────────────────────────────────────────────────────────────
// Miller-Rabin Primality Test
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Miller-Rabin primality test.
 * Returns true if n is probably prime (false positives < 4^(-rounds)).
 *
 * @param {BigInt} n      candidate prime
 * @param {number} rounds number of witnesses (40 = very strong)
 */
function millerRabin(n, rounds = 40) {
	if (n < 2n) return false;
	if (n === 2n || n === 3n) return true;
	if (n % 2n === 0n) return false;

	// Write n-1 as 2^r * d
	let d = n - 1n;
	let r = 0n;
	while (d % 2n === 0n) {
		d /= 2n;
		r++;
	}

	// Test with `rounds` random witnesses
	for (let i = 0; i < rounds; i++) {
		const a = randomBigInt(2n, n - 2n);
		let x = modPow(a, d, n);

		if (x === 1n || x === n - 1n) continue;

		let composite = true;
		for (let j = 0n; j < r - 1n; j++) {
			x = modPow(x, 2n, n);
			if (x === n - 1n) {
				composite = false;
				break;
			}
		}

		if (composite) return false;
	}

	return true; // probably prime
}

/**
 * Generate a random prime of exactly `bits` bits.
 * Sets the top two bits (ensures bit length) and bottom bit (ensures odd).
 */
function generatePrime(bits) {
	const bytes = bits / 8;
	while (true) {
		const buf = randomBytes(bytes);
		// Set MSB and second MSB to 1 (ensures exactly `bits` bits, and that
		// p*q has the right size)
		buf[0] |= 0xc0;
		// Set LSB to 1 (must be odd to be prime)
		buf[bytes - 1] |= 0x01;

		const candidate = bytesToBigInt(buf);
		if (millerRabin(candidate)) {
			return candidate;
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RSA Key Generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate an RSA-2048 key pair.
 *
 * @returns {{ publicKey: { n: BigInt, e: BigInt },
 *             privateKey: { n: BigInt, d: BigInt, p: BigInt, q: BigInt } }}
 */
export function generateKeyPair() {
	const halfBits = KEY_BITS / 2; // 1024 bits each

	let p, q, n, phi, d;

	// Ensure p !== q and that d is large enough (> 2^(KEY_BITS/4))
	while (true) {
		p = generatePrime(halfBits);
		q = generatePrime(halfBits);

		if (p === q) continue;

		n = p * q;
		if (n.toString(2).length !== KEY_BITS) continue; // exact bit length check

		phi = (p - 1n) * (q - 1n);

		// e must be coprime to phi — 65537 is almost always coprime
		// (fail is astronomically unlikely but we check)
		try {
			d = modInverse(E, phi);
		} catch {
			continue;
		}

		// d should be large — if tiny, regenerate (Wiener attack protection)
		if (d < 2n ** BigInt(KEY_BITS / 4)) continue;

		break;
	}

	return {
		publicKey: { n, e: E },
		privateKey: { n, d, p, q },
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// OAEP Padding (MGF1-SHA256)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * MGF1 mask generation function using SHA-256.
 * Generates `maskLen` bytes of pseudorandom output from `seed`.
 *
 * @param {Uint8Array} seed
 * @param {number} maskLen
 * @returns {Uint8Array}
 */
function mgf1(seed, maskLen) {
	const chunks = [];
	const hLen = HASH_LEN;
	const needed = Math.ceil(maskLen / hLen);

	for (let counter = 0; counter < needed; counter++) {
		// C = I2OSP(counter, 4)
		const C = new Uint8Array(4);
		new DataView(C.buffer).setUint32(0, counter, false);
		// FIX 1: always pass Uint8Array to sha256 — never a raw string
		chunks.push(sha256(concatBytes(seed, C)));
	}

	const mask = concatBytes(...chunks);
	return mask.subarray(0, maskLen);
}

/**
 * OAEP Encode (per RFC 8017 §7.1.1).
 *
 * EM = 0x00 || maskedSeed || maskedDB
 *
 * @param {Uint8Array} message   plaintext bytes (max MAX_CHUNK_BYTES)
 * @param {string}     label     optional label (default empty)
 * @returns {Uint8Array}         encoded message block of length KEY_BYTES
 */
function oaepEncode(message, label = "") {
	const mLen = message.length;
	const emLen = KEY_BYTES;

	if (mLen > emLen - 2 * HASH_LEN - 2) {
		throw new Error(
			`OAEP: message too long (${mLen} > ${emLen - 2 * HASH_LEN - 2})`,
		);
	}

	// FIX 1: encode label to bytes before hashing so sha256 always receives
	// a Uint8Array, consistent with the mgf1 call above.
	const lHash = sha256(new TextEncoder().encode(label));

	// DB = lHash || PS || 0x01 || M
	const psLen = emLen - mLen - 2 * HASH_LEN - 2;
	const DB = new Uint8Array(emLen - HASH_LEN - 1);
	let offset = 0;
	DB.set(lHash, offset);
	offset += HASH_LEN;
	// PS: psLen zero bytes (already zero from new Uint8Array)
	offset += psLen;
	DB[offset] = 0x01;
	offset += 1;
	DB.set(message, offset);

	// Random seed
	const seed = randomBytes(HASH_LEN);

	// dbMask = MGF1(seed, emLen - hLen - 1)
	const dbMask = mgf1(seed, emLen - HASH_LEN - 1);

	// maskedDB = DB XOR dbMask
	const maskedDB = new Uint8Array(DB.length);
	for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];

	// seedMask = MGF1(maskedDB, hLen)
	const seedMask = mgf1(maskedDB, HASH_LEN);

	// maskedSeed = seed XOR seedMask
	const maskedSeed = new Uint8Array(HASH_LEN);
	for (let i = 0; i < HASH_LEN; i++) maskedSeed[i] = seed[i] ^ seedMask[i];

	// EM = 0x00 || maskedSeed || maskedDB
	const EM = new Uint8Array(emLen);
	EM[0] = 0x00;
	EM.set(maskedSeed, 1);
	EM.set(maskedDB, 1 + HASH_LEN);

	return EM;
}

/**
 * OAEP Decode (per RFC 8017 §7.1.2).
 *
 * @param {Uint8Array} EM     encoded message block of length KEY_BYTES
 * @param {string}     label  must match the label used during encoding
 * @returns {Uint8Array}      recovered plaintext bytes
 */
function oaepDecode(EM, label = "") {
	const emLen = KEY_BYTES;

	if (EM.length !== emLen) throw new Error("OAEP decode: invalid EM length");
	if (EM[0] !== 0x00) throw new Error("OAEP decode: invalid first byte");

	const maskedSeed = EM.subarray(1, 1 + HASH_LEN);
	const maskedDB = EM.subarray(1 + HASH_LEN);

	// Recover seed
	const seedMask = mgf1(maskedDB, HASH_LEN);
	const seed = new Uint8Array(HASH_LEN);
	for (let i = 0; i < HASH_LEN; i++) seed[i] = maskedSeed[i] ^ seedMask[i];

	// Recover DB
	const dbMask = mgf1(seed, emLen - HASH_LEN - 1);
	const DB = new Uint8Array(maskedDB.length);
	for (let i = 0; i < maskedDB.length; i++) DB[i] = maskedDB[i] ^ dbMask[i];

	// FIX 1: encode label to bytes before hashing (matches oaepEncode)
	const lHash = sha256(new TextEncoder().encode(label));
	for (let i = 0; i < HASH_LEN; i++) {
		if (DB[i] !== lHash[i]) throw new Error("OAEP decode: label hash mismatch");
	}

	// Find 0x01 separator after PS
	let msgStart = HASH_LEN;
	while (msgStart < DB.length && DB[msgStart] === 0x00) msgStart++;
	if (DB[msgStart] !== 0x01)
		throw new Error("OAEP decode: missing 0x01 separator");

	return DB.subarray(msgStart + 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// RSA-OAEP Encrypt / Decrypt
// ─────────────────────────────────────────────────────────────────────────────

/**
 * RSA-OAEP encrypt a short message (must fit in one block ≤ MAX_CHUNK_BYTES bytes).
 *
 * @param {string|Uint8Array} message
 * @param {{ n: BigInt, e: BigInt }} publicKey
 * @returns {string} base64 ciphertext
 */
export function encrypt(message, publicKey) {
	const { n, e } = publicKey;
	const msgBytes =
		typeof message === "string" ? new TextEncoder().encode(message) : message;

	// OAEP pad
	const EM = oaepEncode(msgBytes);

	// RSA: c = m^e mod n
	const m = os2ip(EM);
	const c = modPow(m, e, n);

	// Encode to KEY_BYTES-length byte array, then base64
	return toBase64(i2osp(c, KEY_BYTES));
}

/**
 * RSA-OAEP decrypt a single block.
 *
 * @param {string} ciphertext  base64 string
 * @param {{ n: BigInt, d: BigInt }} privateKey
 * @returns {string} plaintext
 */
export function decrypt(ciphertext, privateKey) {
	const { n, d } = privateKey;
	const cBytes = fromBase64(ciphertext);

	// RSA: m = c^d mod n
	const c = os2ip(cBytes);
	const m = modPow(c, d, n);

	// Decode to fixed-width byte array
	const EM = i2osp(m, KEY_BYTES);

	// OAEP unpad
	const msgBytes = oaepDecode(EM);

	return new TextDecoder().decode(msgBytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// Chunk Encrypt / Decrypt (for long messages)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encrypt a string of any length by splitting into CHUNK_SIZE character chunks.
 * Each chunk is independently RSA-OAEP encrypted.
 *
 * @param {string} longString
 * @param {{ n: BigInt, e: BigInt }} publicKey
 * @returns {string[]} array of base64 ciphertext strings
 */
export function chunkEncrypt(longString, publicKey) {
	if (!longString) return [];
	const chunks = [];
	for (let i = 0; i < longString.length; i += CHUNK_SIZE) {
		chunks.push(longString.slice(i, i + CHUNK_SIZE));
	}
	return chunks.map((chunk) => encrypt(chunk, publicKey));
}

/**
 * Decrypt an array of RSA-OAEP encrypted chunks back into a single string.
 *
 * @param {string[]} chunks  array of base64 ciphertext strings
 * @param {{ n: BigInt, d: BigInt }} privateKey
 * @returns {string} reassembled plaintext
 */
export function chunkDecrypt(chunks, privateKey) {
	if (!chunks || chunks.length === 0) return "";
	return chunks.map((chunk) => decrypt(chunk, privateKey)).join("");
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Serialisation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Serialize a public key to a base64 JSON string for database storage.
 * Stores n and e as hex strings (BigInt can't be JSON.stringify'd directly).
 *
 * @param {{ n: BigInt, e: BigInt }} publicKey
 * @returns {string} base64 string
 */
export function serializePublicKey(publicKey) {
	const obj = {
		n: publicKey.n.toString(16),
		e: publicKey.e.toString(16),
	};
	return toBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * Deserialize a public key from a base64 JSON string.
 *
 * Accepts three formats:
 *   1. Raw JSON string with hex-encoded n/e  (our serializePublicKey format)
 *   2. Base64 of the above JSON              (our serializePublicKey output)
 *   3. JWK JSON with base64url-encoded n/e   (standard JWK)
 *
 * @param {string} input
 * @returns {{ n: BigInt, e: BigInt }}
 */
export function deserializePublicKey(input) {
	if (typeof input !== "string" || input.trim().length === 0) {
		throw new Error("Missing RSA public key");
	}

	const trimmed = input.trim();

	// CASE 1: already raw JSON
	if (trimmed.startsWith("{")) {
		return parsePublicKeyJSON(JSON.parse(trimmed));
	}

	// CASE 2: PEM — not supported
	if (trimmed.includes("BEGIN PUBLIC KEY")) {
		throw new Error(
			"PEM format detected. Convert to JWK or use serializePublicKey format.",
		);
	}

	let decodedText;
	try {
		decodedText = Buffer.from(trimmed, "base64url").toString("utf8");
		// Fall back to standard base64 if base64url produced non-printable output
		if (!decodedText.startsWith("{")) {
			decodedText = Buffer.from(trimmed, "base64").toString("utf8");
		}
	} catch {
		throw new Error("Invalid Base64 encoding");
	}

	
	if (decodedText.startsWith("{")) {
		return parsePublicKeyJSON(JSON.parse(decodedText));
	}

	throw new Error(
		"Unsupported RSA key format (likely DER/binary). Expected JWK JSON or serializePublicKey output.",
	);
}

/**
 * Parse a public-key JSON object whose n/e fields are either:
 *   - lowercase hex strings  (our custom serialisation format), or
 *   - base64url strings      (standard JWK format).
 *
 * FIX 4: renamed internal helper from `toHex` → `b64urlToHex` so it no
 * longer shadows the `toHex` import from utils.js.
 *
 * FIX 5: detect the encoding format from the field value itself, so that
 * keys produced by serializePublicKey round-trip correctly through
 * deserializePublicKey.
 *
 * @param {object} obj
 * @returns {{ n: BigInt, e: BigInt }}
 */
function parsePublicKeyJSON(obj) {
	if (!obj.n || !obj.e) {
		throw new Error("Invalid public key JSON: missing n or e fields");
	}

	/**
	 * Convert a base64url string to a lowercase hex string.
	 * FIX 4: renamed from toHex → b64urlToHex to avoid shadowing the import.
	 */
	function b64urlToHex(val) {
		// Normalise base64url → standard base64
		let b64 = val.replace(/-/g, "+").replace(/_/g, "/");
		while (b64.length % 4 !== 0) b64 += "=";
		const bytes = fromBase64(b64); // FIX 2: use imported util, not Buffer
		return Array.from(bytes)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
	}

	/**
	 * FIX 5: return the BigInt for a key field regardless of whether the
	 * stored value is a plain hex string (our format) or base64url (JWK).
	 *
	 * Detection rule: if the value contains only hex digits [0-9a-fA-F] it is
	 * already a hex string; otherwise treat it as base64url.
	 */
	function fieldToBigInt(val) {
		if (/^[0-9a-fA-F]+$/.test(val)) {
			// Our custom format — value is already a hex string
			return BigInt("0x" + val);
		}
		// JWK format — value is base64url-encoded big-endian bytes
		return BigInt("0x" + b64urlToHex(val));
	}

	return {
		n: fieldToBigInt(obj.n),
		e: fieldToBigInt(obj.e),
	};
}

/**
 * Serialize a private key to a base64 JSON string.
 * WARNING: This should always be encrypted before storage (see keyManager.js).
 *
 * @param {{ n: BigInt, d: BigInt, p: BigInt, q: BigInt }} privateKey
 * @returns {string} base64 string
 */
export function serializePrivateKey(privateKey) {
	const obj = {
		n: privateKey.n.toString(16),
		d: privateKey.d.toString(16),
		p: privateKey.p.toString(16),
		q: privateKey.q.toString(16),
	};
	return toBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * Deserialize a private key from a base64 JSON string.
 *
 * @param {string} b64
 * @returns {{ n: BigInt, d: BigInt, p: BigInt, q: BigInt }}
 */
export function deserializePrivateKey(b64) {
	const trimmed = b64.trim();
	const jsonText = trimmed.startsWith("{")
		? trimmed
		: new TextDecoder().decode(fromBase64(trimmed));
	const obj = JSON.parse(jsonText);
	if (!obj?.n || !obj?.d || !obj?.p || !obj?.q) {
		throw new Error("Invalid RSA private key format");
	}
	return {
		n: BigInt("0x" + obj.n),
		d: BigInt("0x" + obj.d),
		p: BigInt("0x" + obj.p),
		q: BigInt("0x" + obj.q),
	};
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
	generateKeyPair,
	encrypt,
	decrypt,
	chunkEncrypt,
	chunkDecrypt,
	serializePublicKey,
	deserializePublicKey,
	serializePrivateKey,
	deserializePrivateKey,
	MAX_CHUNK_BYTES,
	CHUNK_SIZE,
};
