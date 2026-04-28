/**
 * crypto/ecc.js
 *
 * Elliptic Curve Cryptography on secp256k1 — implemented from scratch.
 * No elliptic npm, no noble-curves, no OpenSSL bindings. Pure BigInt.
 *
 * Implements:
 *   - secp256k1 curve parameters
 *   - Point addition, doubling, scalar multiplication
 *   - Key pair generation
 *   - ECIES (Elliptic Curve Integrated Encryption Scheme)
 *       - XOR stream cipher keyed from ECDH shared secret + SHA-256
 *       - HMAC-SHA256 authentication tag
 *   - Key serialisation to/from base64
 *
 * Exports:
 *   generateKeyPair()                          → { privateKey, publicKey }
 *   encrypt(message, publicKey)                → base64 ciphertext blob
 *   decrypt(ciphertext, privateKey)            → string plaintext
 *   serializePublicKey(publicKey)              → base64 string
 *   deserializePublicKey(base64)               → publicKey point object
 *   serializePrivateKey(privateKey)            → base64 string (hex scalar)
 *   deserializePrivateKey(base64)              → BigInt scalar
 */

import { sha256, hmacSha256 } from "./hmac.js";
import {
	randomBigInt,
	randomBytes,
	toBase64,
	fromBase64,
	toHex,
	fromHex,
	bigIntToBytes,
	bytesToBigInt,
	concatBytes,
	constantTimeEqual,
} from "./utils.js";

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 Curve Parameters
// (https://www.secg.org/sec2-v2.pdf §2.4.1)
// ─────────────────────────────────────────────────────────────────────────────

const CURVE = {
	// Field prime
	p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
	// Curve coefficients: y² = x³ + ax + b  (a=0, b=7 for secp256k1)
	a: 0n,
	b: 7n,
	// Generator point
	Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
	Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
	// Curve order (number of points on the curve)
	n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
};

// Point at infinity (identity element for elliptic curve group)
const POINT_AT_INFINITY = { x: null, y: null };

/** Scalar size in bytes */
const SCALAR_BYTES = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Modular arithmetic on the field
// ─────────────────────────────────────────────────────────────────────────────

/** a mod p, always positive */
const mod = (a) => ((a % CURVE.p) + CURVE.p) % CURVE.p;

/** Modular inverse mod p using extended Euclidean */
function fieldInverse(a) {
	// For a prime field, a^(-1) = a^(p-2) mod p (Fermat's little theorem)
	// Using fast exponentiation is equivalent and avoids recursive stack depth
	return modPow(((a % CURVE.p) + CURVE.p) % CURVE.p, CURVE.p - 2n, CURVE.p);
}

/** Modular exponentiation — imported from utils but inlined here for self-containment */
function modPow(base, exp, mod) {
	if (mod === 1n) return 0n;
	let result = 1n;
	base = base % mod;
	while (exp > 0n) {
		if (exp % 2n === 1n) result = (result * base) % mod;
		exp >>= 1n;
		base = (base * base) % mod;
	}
	return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Point arithmetic
// ─────────────────────────────────────────────────────────────────────────────

/** Check if a point is the point at infinity */
function isInfinity(P) {
	return P.x === null && P.y === null;
}

/**
 * Verify a point is on the secp256k1 curve.
 * y² ≡ x³ + 7 (mod p)
 */
function isOnCurve(P) {
	if (isInfinity(P)) return true;
	const { x, y } = P;
	const lhs = mod(y * y);
	const rhs = mod(x * x * x + CURVE.b);
	return lhs === rhs;
}

/**
 * Point doubling: P + P
 * Formula (affine coordinates):
 *   λ = (3x² + a) / (2y)  mod p
 *   x₃ = λ² - 2x          mod p
 *   y₃ = λ(x - x₃) - y    mod p
 */
function pointDouble(P) {
	if (isInfinity(P)) return POINT_AT_INFINITY;

	const { x, y } = P;
	// λ = (3x² + a) * (2y)^(-1) mod p
	const lambda = mod((3n * x * x + CURVE.a) * fieldInverse(2n * y));
	const x3 = mod(lambda * lambda - 2n * x);
	const y3 = mod(lambda * (x - x3) - y);

	return { x: x3, y: y3 };
}

/**
 * Point addition: P + Q
 * Formula (affine coordinates):
 *   λ = (y₂ - y₁) / (x₂ - x₁)  mod p
 *   x₃ = λ² - x₁ - x₂            mod p
 *   y₃ = λ(x₁ - x₃) - y₁         mod p
 */
function pointAdd(P, Q) {
	if (isInfinity(P)) return Q;
	if (isInfinity(Q)) return P;

	// Same x → either P === Q (double) or P === -Q (infinity)
	if (P.x === Q.x) {
		if (P.y === Q.y) return pointDouble(P);
		return POINT_AT_INFINITY; // P + (-P) = O
	}

	const lambda = mod((Q.y - P.y) * fieldInverse(Q.x - P.x));
	const x3 = mod(lambda * lambda - P.x - Q.x);
	const y3 = mod(lambda * (P.x - x3) - P.y);

	return { x: x3, y: y3 };
}

/**
 * Scalar multiplication: k * P using the double-and-add algorithm.
 * Processes bits of k from MSB to LSB.
 *
 * @param {BigInt} k  scalar
 * @param {{ x: BigInt, y: BigInt }} P  curve point
 * @returns {{ x: BigInt, y: BigInt }}
 */
export function scalarMult(k, P) {
	if (k === 0n) return POINT_AT_INFINITY;
	if (k < 0n) {
		// Negate P: (x, -y mod p)
		return scalarMult(-k, { x: P.x, y: mod(-P.y) });
	}

	let result = POINT_AT_INFINITY;
	let addend = { x: P.x, y: P.y };

	while (k > 0n) {
		if (k & 1n) {
			result = pointAdd(result, addend);
		}
		addend = pointDouble(addend);
		k >>= 1n;
	}

	return result;
}

// Generator point shorthand
const G = { x: CURVE.Gx, y: CURVE.Gy };

// ─────────────────────────────────────────────────────────────────────────────
// Key Generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate an ECC key pair on secp256k1.
 *
 * @returns {{
 *   privateKey: BigInt,
 *   publicKey: { x: BigInt, y: BigInt }
 * }}
 */
export function generateKeyPair() {
	// Private key: random scalar in [1, n-1]
	const privateKey = randomBigInt(1n, CURVE.n);
	// Public key: private_key * G
	const publicKey = scalarMult(privateKey, G);

	if (!isOnCurve(publicKey)) {
		throw new Error(
			"Generated public key is not on curve — this should never happen",
		);
	}

	return { privateKey, publicKey };
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES Key Derivation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive an encryption key stream byte from the ECDH shared secret.
 *
 * For each byte index i, we compute:
 *   keyByte_i = SHA256(sharedX_bytes || i2bytes(i))[0]
 *
 * This creates a deterministic, indistinguishable-from-random key stream
 * without using any symmetric cipher.
 *
 * @param {BigInt} sharedX  x-coordinate of ECDH shared point
 * @param {number} length   number of key bytes to generate
 * @returns {Uint8Array}    key stream
 */
function deriveKeyStream(sharedX, length) {
	const sharedBytes = bigIntToBytes(sharedX, SCALAR_BYTES);
	const stream = new Uint8Array(length);
	const hashSize = 32;

	for (let block = 0; block * hashSize < length; block++) {
		const counter = new Uint8Array(4);
		new DataView(counter.buffer).setUint32(0, block, false);
		const h = sha256(concatBytes(sharedBytes, counter));
		const start = block * hashSize;
		const end = Math.min(start + hashSize, length);
		stream.set(h.subarray(0, end - start), start);
	}

	return stream;
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES Encrypt / Decrypt
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ECIES Encrypt.
 *
 * Steps:
 *   1. Generate ephemeral key pair (r, R = r*G)
 *   2. Compute ECDH shared point: S = r * recipientPublicKey
 *   3. Derive key stream from S.x
 *   4. XOR message bytes with key stream → ciphertext
 *   5. Compute HMAC-SHA256(S.x_bytes, ciphertext) → auth tag
 *   6. Output: base64( R_compressed || tag || ciphertext )
 *
 * @param {string|Uint8Array} message
 * @param {{ x: BigInt, y: BigInt }} recipientPublicKey
 * @returns {string} base64 blob
 */
export function encrypt(message, recipientPublicKey) {
	if (!isOnCurve(recipientPublicKey)) {
		throw new Error("ECIES encrypt: recipient public key is not on curve");
	}

	const msgBytes =
		typeof message === "string" ? new TextEncoder().encode(message) : message;

	// 1. Ephemeral key pair
	const { privateKey: r, publicKey: R } = generateKeyPair();

	// 2. ECDH: S = r * recipientPublicKey
	const S = scalarMult(r, recipientPublicKey);

	// 3. Key stream from shared secret
	const keyStream = deriveKeyStream(S.x, msgBytes.length);

	// 4. XOR encrypt
	const ciphertext = new Uint8Array(msgBytes.length);
	for (let i = 0; i < msgBytes.length; i++) {
		ciphertext[i] = msgBytes[i] ^ keyStream[i];
	}

	// 5. HMAC auth tag: HMAC(S.x_bytes, ciphertext)
	const sharedBytes = bigIntToBytes(S.x, SCALAR_BYTES);
	const tag = hmacSha256(sharedBytes, ciphertext);

	// 6. Serialize R as compressed point: 02/03 prefix + 32-byte x
	const RCompressed = compressPoint(R);

	// Pack: R_compressed (33 bytes) || tag (32 bytes) || ciphertext (variable)
	const blob = concatBytes(RCompressed, tag, ciphertext);
	return toBase64(blob);
}

/**
 * ECIES Decrypt.
 *
 * Steps:
 *   1. Parse R, tag, ciphertext from blob
 *   2. Compute ECDH shared point: S = recipientPrivateKey * R
 *   3. Verify HMAC tag
 *   4. Derive key stream, XOR to recover plaintext
 *
 * @param {string} ciphertextBlob  base64 string from encrypt()
 * @param {BigInt} recipientPrivateKey
 * @returns {string} plaintext
 */
export function decrypt(ciphertextBlob, recipientPrivateKey) {
	const blob = fromBase64(ciphertextBlob);

	// Parse: 33 bytes R | 32 bytes tag | rest = ciphertext
	if (blob.length < 33 + 32 + 1) {
		throw new Error("ECIES decrypt: blob too short");
	}

	const RCompressed = blob.subarray(0, 33);
	const tag = blob.subarray(33, 65);
	const ciphertext = blob.subarray(65);

	// 1. Decompress R
	const R = decompressPoint(RCompressed);

	// 2. ECDH
	const S = scalarMult(recipientPrivateKey, R);

	// 3. Verify tag
	const sharedBytes = bigIntToBytes(S.x, SCALAR_BYTES);
	const expectedTag = hmacSha256(sharedBytes, ciphertext);
	if (!constantTimeEqual(expectedTag, tag)) {
		throw new Error(
			"ECIES decrypt: authentication tag mismatch — data may be tampered",
		);
	}

	// 4. XOR decrypt
	const keyStream = deriveKeyStream(S.x, ciphertext.length);
	const plainBytes = new Uint8Array(ciphertext.length);
	for (let i = 0; i < ciphertext.length; i++) {
		plainBytes[i] = ciphertext[i] ^ keyStream[i];
	}

	return new TextDecoder().decode(plainBytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// Point Compression / Decompression
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compress a curve point to 33 bytes: prefix byte + 32-byte x.
 * Prefix: 0x02 if y is even, 0x03 if y is odd.
 */
function compressPoint(P) {
	const prefix = P.y % 2n === 0n ? 0x02 : 0x03;
	const xBytes = bigIntToBytes(P.x, SCALAR_BYTES);
	const result = new Uint8Array(33);
	result[0] = prefix;
	result.set(xBytes, 1);
	return result;
}

/**
 * Decompress a 33-byte compressed point back to (x, y).
 * Uses the curve equation to recover y from x.
 */
function decompressPoint(compressed) {
	if (compressed.length !== 33)
		throw new Error("decompressPoint: must be 33 bytes");
	const prefix = compressed[0];
	if (prefix !== 0x02 && prefix !== 0x03)
		throw new Error("decompressPoint: invalid prefix");

	const x = bytesToBigInt(compressed.subarray(1));

	// y² = x³ + 7 mod p
	const rhs = mod(x * x * x + CURVE.b);

	// Compute modular square root: y = rhs^((p+1)/4) mod p
	// (works because p ≡ 3 mod 4 for secp256k1)
	const sqrtExp = (CURVE.p + 1n) / 4n;
	let y = modPow(rhs, sqrtExp, CURVE.p);

	// Choose the correct root based on parity
	if ((y % 2n === 0n) !== (prefix === 0x02)) {
		y = CURVE.p - y;
	}

	const P = { x, y };
	if (!isOnCurve(P))
		throw new Error("decompressPoint: recovered point not on curve");
	return P;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Serialisation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Serialize a public key point to a base64 compressed-point string (33 bytes → base64).
 *
 * @param {{ x: BigInt, y: BigInt }} publicKey
 * @returns {string} base64 string (44 chars)
 */
export function serializePublicKey(publicKey) {
	return toBase64(compressPoint(publicKey));
}

/**
 * Deserialize a compressed-point base64 string to a public key point.
 *
 * @param {string} b64
 * @returns {{ x: BigInt, y: BigInt }}
 */
export function deserializePublicKey(b64) {
	return decompressPoint(fromBase64(b64));
}

/**
 * Serialize a private key (BigInt scalar) to a base64 string.
 * WARNING: Must be encrypted before database storage.
 *
 * @param {BigInt} privateKey
 * @returns {string} base64 string
 */
export function serializePrivateKey(privateKey) {
	return toBase64(bigIntToBytes(privateKey, SCALAR_BYTES));
}

/**
 * Deserialize a private key from base64 to a BigInt scalar.
 *
 * @param {string} b64
 * @returns {BigInt}
 */
export function deserializePrivateKey(b64) {
	return bytesToBigInt(fromBase64(b64));
}

// ─────────────────────────────────────────────────────────────────────────────
// Default export
// ─────────────────────────────────────────────────────────────────────────────

export default {
	generateKeyPair,
	encrypt,
	decrypt,
	scalarMult,
	serializePublicKey,
	deserializePublicKey,
	serializePrivateKey,
	deserializePrivateKey,
	CURVE,
};
