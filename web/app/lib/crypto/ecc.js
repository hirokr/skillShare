/**
 * crypto/ecc.js
 * Browser-friendly ECC/ECIES implementation.
 */

import { sha256, hmacSha256 } from "./hmac.js";
import {
	randomBigInt,
	randomBytes,
	toBase64,
	fromBase64,
	bigIntToBytes,
	bytesToBigInt,
	concatBytes,
	constantTimeEqual,
} from "./utils.js";

const CURVE = {
	p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
	a: 0n,
	b: 7n,
	Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
	Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
	n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
};

const POINT_AT_INFINITY = { x: null, y: null };
const SCALAR_BYTES = 32;

const mod = (a) => ((a % CURVE.p) + CURVE.p) % CURVE.p;

function modPow(base, exp, modValue) {
	if (modValue === 1n) return 0n;
	let result = 1n;
	base = base % modValue;
	while (exp > 0n) {
		if (exp % 2n === 1n) result = (result * base) % modValue;
		exp >>= 1n;
		base = (base * base) % modValue;
	}
	return result;
}

function fieldInverse(a) {
	return modPow(((a % CURVE.p) + CURVE.p) % CURVE.p, CURVE.p - 2n, CURVE.p);
}

function isInfinity(P) {
	return P.x === null && P.y === null;
}

function isOnCurve(P) {
	if (isInfinity(P)) return true;
	const { x, y } = P;
	const lhs = mod(y * y);
	const rhs = mod(x * x * x + CURVE.b);
	return lhs === rhs;
}

function pointDouble(P) {
	if (isInfinity(P)) return POINT_AT_INFINITY;

	const { x, y } = P;
	const lambda = mod((3n * x * x + CURVE.a) * fieldInverse(2n * y));
	const x3 = mod(lambda * lambda - 2n * x);
	const y3 = mod(lambda * (x - x3) - y);

	return { x: x3, y: y3 };
}

function pointAdd(P, Q) {
	if (isInfinity(P)) return Q;
	if (isInfinity(Q)) return P;

	if (P.x === Q.x) {
		if (P.y === Q.y) return pointDouble(P);
		return POINT_AT_INFINITY;
	}

	const lambda = mod((Q.y - P.y) * fieldInverse(Q.x - P.x));
	const x3 = mod(lambda * lambda - P.x - Q.x);
	const y3 = mod(lambda * (P.x - x3) - P.y);

	return { x: x3, y: y3 };
}

export function scalarMult(k, P) {
	if (k === 0n) return POINT_AT_INFINITY;
	if (k < 0n) {
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

const G = { x: CURVE.Gx, y: CURVE.Gy };

export function generateKeyPair() {
	const privateKey = randomBigInt(1n, CURVE.n);
	const publicKey = scalarMult(privateKey, G);

	if (!isOnCurve(publicKey)) {
		throw new Error("Generated public key is not on curve");
	}

	return { privateKey, publicKey };
}

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

export function encrypt(message, recipientPublicKey) {
	if (!isOnCurve(recipientPublicKey)) {
		throw new Error("ECIES encrypt: recipient public key is not on curve");
	}

	const msgBytes =
		typeof message === "string" ? new TextEncoder().encode(message) : message;

	const { privateKey: r, publicKey: R } = generateKeyPair();
	const S = scalarMult(r, recipientPublicKey);
	const keyStream = deriveKeyStream(S.x, msgBytes.length);

	const ciphertext = new Uint8Array(msgBytes.length);
	for (let i = 0; i < msgBytes.length; i++) {
		ciphertext[i] = msgBytes[i] ^ keyStream[i];
	}

	const sharedBytes = bigIntToBytes(S.x, SCALAR_BYTES);
	const tag = hmacSha256(sharedBytes, ciphertext);
	const RCompressed = compressPoint(R);

	const blob = concatBytes(RCompressed, tag, ciphertext);
	return toBase64(blob);
}

export function decrypt(ciphertextBlob, recipientPrivateKey) {
	const blob = fromBase64(ciphertextBlob);
	if (blob.length < 33 + 32 + 1) {
		throw new Error("ECIES decrypt: blob too short");
	}

	const RCompressed = blob.subarray(0, 33);
	const tag = blob.subarray(33, 65);
	const ciphertext = blob.subarray(65);

	const R = decompressPoint(RCompressed);
	const S = scalarMult(recipientPrivateKey, R);

	const sharedBytes = bigIntToBytes(S.x, SCALAR_BYTES);
	const expectedTag = hmacSha256(sharedBytes, ciphertext);
	if (!constantTimeEqual(expectedTag, tag)) {
		throw new Error("ECIES decrypt: authentication tag mismatch");
	}

	const keyStream = deriveKeyStream(S.x, ciphertext.length);
	const plainBytes = new Uint8Array(ciphertext.length);
	for (let i = 0; i < ciphertext.length; i++) {
		plainBytes[i] = ciphertext[i] ^ keyStream[i];
	}

	return new TextDecoder().decode(plainBytes);
}

function compressPoint(P) {
	const prefix = P.y % 2n === 0n ? 0x02 : 0x03;
	const xBytes = bigIntToBytes(P.x, SCALAR_BYTES);
	const result = new Uint8Array(33);
	result[0] = prefix;
	result.set(xBytes, 1);
	return result;
}

function decompressPoint(compressed) {
	if (compressed.length !== 33)
		throw new Error("decompressPoint: must be 33 bytes");
	const prefix = compressed[0];
	if (prefix !== 0x02 && prefix !== 0x03)
		throw new Error("decompressPoint: invalid prefix");

	const x = bytesToBigInt(compressed.subarray(1));
	const rhs = mod(x * x * x + CURVE.b);
	const sqrtExp = (CURVE.p + 1n) / 4n;
	let y = modPow(rhs, sqrtExp, CURVE.p);

	if ((y % 2n === 0n) !== (prefix === 0x02)) {
		y = CURVE.p - y;
	}

	const P = { x, y };
	if (!isOnCurve(P))
		throw new Error("decompressPoint: recovered point not on curve");
	return P;
}

export function serializePublicKey(publicKey) {
	return toBase64(compressPoint(publicKey));
}

export function deserializePublicKey(b64) {
	return decompressPoint(fromBase64(b64));
}

export function serializePrivateKey(privateKey) {
	return toBase64(bigIntToBytes(privateKey, SCALAR_BYTES));
}

export function deserializePrivateKey(b64) {
	return bytesToBigInt(fromBase64(b64));
}

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
