/**
 * crypto/rsa.js
 * Browser-friendly RSA-OAEP implementation.
 */

import { sha256 } from "./hmac.js";
import {
	randomBytes,
	randomBigInt,
	modPow,
	modInverse,
	toBase64,
	fromBase64,
	bigIntToBytes,
	bytesToBigInt,
	concatBytes,
	i2osp,
	os2ip,
} from "./utils.js";

const KEY_BITS = 2048;
const KEY_BYTES = KEY_BITS / 8;
const E = 65537n;

const HASH_LEN = 32;
export const MAX_CHUNK_BYTES = KEY_BYTES - 2 * HASH_LEN - 2;
export const CHUNK_SIZE = 120;

function millerRabin(n, rounds = 40) {
	if (n < 2n) return false;
	if (n === 2n || n === 3n) return true;
	if (n % 2n === 0n) return false;

	let d = n - 1n;
	let r = 0n;
	while (d % 2n === 0n) {
		d /= 2n;
		r++;
	}

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

	return true;
}

function generatePrime(bits) {
	const bytes = bits / 8;
	while (true) {
		const buf = randomBytes(bytes);
		buf[0] |= 0xc0;
		buf[bytes - 1] |= 0x01;

		const candidate = bytesToBigInt(buf);
		if (millerRabin(candidate)) {
			return candidate;
		}
	}
}

export function generateKeyPair() {
	const halfBits = KEY_BITS / 2;
	let p, q, n, phi, d;

	while (true) {
		p = generatePrime(halfBits);
		q = generatePrime(halfBits);

		if (p === q) continue;

		n = p * q;
		if (n.toString(2).length !== KEY_BITS) continue;

		phi = (p - 1n) * (q - 1n);

		try {
			d = modInverse(E, phi);
		} catch {
			continue;
		}

		if (d < 2n ** BigInt(KEY_BITS / 4)) continue;
		break;
	}

	return {
		publicKey: { n, e: E },
		privateKey: { n, d, p, q },
	};
}

function mgf1(seed, maskLen) {
	const chunks = [];
	const hLen = HASH_LEN;
	const needed = Math.ceil(maskLen / hLen);

	for (let counter = 0; counter < needed; counter++) {
		const C = new Uint8Array(4);
		new DataView(C.buffer).setUint32(0, counter, false);
		chunks.push(sha256(concatBytes(seed, C)));
	}

	const mask = concatBytes(...chunks);
	return mask.subarray(0, maskLen);
}

function oaepEncode(message, label = "") {
	const mLen = message.length;
	const emLen = KEY_BYTES;

	if (mLen > emLen - 2 * HASH_LEN - 2) {
		throw new Error(
			`OAEP: message too long (${mLen} > ${emLen - 2 * HASH_LEN - 2})`,
		);
	}

	const lHash = sha256(label);

	const psLen = emLen - mLen - 2 * HASH_LEN - 2;
	const DB = new Uint8Array(emLen - HASH_LEN - 1);
	let offset = 0;
	DB.set(lHash, offset);
	offset += HASH_LEN;
	offset += psLen;
	DB[offset] = 0x01;
	offset += 1;
	DB.set(message, offset);

	const seed = randomBytes(HASH_LEN);
	const dbMask = mgf1(seed, emLen - HASH_LEN - 1);

	const maskedDB = new Uint8Array(DB.length);
	for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];

	const seedMask = mgf1(maskedDB, HASH_LEN);

	const maskedSeed = new Uint8Array(HASH_LEN);
	for (let i = 0; i < HASH_LEN; i++) maskedSeed[i] = seed[i] ^ seedMask[i];

	const EM = new Uint8Array(emLen);
	EM[0] = 0x00;
	EM.set(maskedSeed, 1);
	EM.set(maskedDB, 1 + HASH_LEN);

	return EM;
}

function oaepDecode(EM, label = "") {
	const emLen = KEY_BYTES;

	if (EM.length !== emLen) throw new Error("OAEP decode: invalid EM length");
	if (EM[0] !== 0x00) throw new Error("OAEP decode: invalid first byte");

	const maskedSeed = EM.subarray(1, 1 + HASH_LEN);
	const maskedDB = EM.subarray(1 + HASH_LEN);

	const seedMask = mgf1(maskedDB, HASH_LEN);
	const seed = new Uint8Array(HASH_LEN);
	for (let i = 0; i < HASH_LEN; i++) seed[i] = maskedSeed[i] ^ seedMask[i];

	const dbMask = mgf1(seed, emLen - HASH_LEN - 1);
	const DB = new Uint8Array(maskedDB.length);
	for (let i = 0; i < maskedDB.length; i++) DB[i] = maskedDB[i] ^ dbMask[i];

	const lHash = sha256(label);
	for (let i = 0; i < HASH_LEN; i++) {
		if (DB[i] !== lHash[i]) throw new Error("OAEP decode: label hash mismatch");
	}

	let msgStart = HASH_LEN;
	while (msgStart < DB.length && DB[msgStart] === 0x00) msgStart++;
	if (DB[msgStart] !== 0x01)
		throw new Error("OAEP decode: missing 0x01 separator");

	return DB.subarray(msgStart + 1);
}

export function encrypt(message, publicKey) {
	const { n, e } = publicKey;
	const msgBytes =
		typeof message === "string" ? new TextEncoder().encode(message) : message;

	const EM = oaepEncode(msgBytes);
	const m = os2ip(EM);
	const c = modPow(m, e, n);

	return toBase64(i2osp(c, KEY_BYTES));
}

export function decrypt(ciphertext, privateKey) {
	const { n, d } = privateKey;
	const cBytes = fromBase64(ciphertext);
	const c = os2ip(cBytes);
	const m = modPow(c, d, n);
	const EM = i2osp(m, KEY_BYTES);
	const msgBytes = oaepDecode(EM);

	return new TextDecoder().decode(msgBytes);
}

export function chunkEncrypt(longString, publicKey) {
	if (!longString) return [];
	const chunks = [];
	for (let i = 0; i < longString.length; i += CHUNK_SIZE) {
		chunks.push(longString.slice(i, i + CHUNK_SIZE));
	}
	return chunks.map((chunk) => encrypt(chunk, publicKey));
}

export function chunkDecrypt(chunks, privateKey) {
	if (!chunks || chunks.length === 0) return "";
	return chunks.map((chunk) => decrypt(chunk, privateKey)).join("");
}

export function serializePublicKey(publicKey) {
	const obj = {
		n: publicKey.n.toString(16),
		e: publicKey.e.toString(16),
	};
	return toBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

export function deserializePublicKey(b64) {
	const obj = JSON.parse(new TextDecoder().decode(fromBase64(b64)));
	return {
		n: BigInt("0x" + obj.n),
		e: BigInt("0x" + obj.e),
	};
}

export function serializePrivateKey(privateKey) {
	const obj = {
		n: privateKey.n.toString(16),
		d: privateKey.d.toString(16),
		p: privateKey.p.toString(16),
		q: privateKey.q.toString(16),
	};
	return toBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

export function deserializePrivateKey(b64) {
	const obj = JSON.parse(new TextDecoder().decode(fromBase64(b64)));
	return {
		n: BigInt("0x" + obj.n),
		d: BigInt("0x" + obj.d),
		p: BigInt("0x" + obj.p),
		q: BigInt("0x" + obj.q),
	};
}

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
