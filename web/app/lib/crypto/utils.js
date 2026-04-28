/**
 * crypto/utils.js
 * Browser-safe crypto helpers.
 */

const getRandomValues = (buf) => {
	if (!globalThis.crypto?.getRandomValues) {
		throw new Error("crypto.getRandomValues is not available");
	}
	return globalThis.crypto.getRandomValues(buf);
};

export function stringToBytes(str) {
	return new TextEncoder().encode(str);
}

export function bytesToString(bytes) {
	return new TextDecoder().decode(bytes);
}

export function toBase64(bytes) {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

export function fromBase64(b64) {
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

export function toHex(bytes) {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export function fromHex(hex) {
	if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
	const result = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return result;
}

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

export function bytesToBigInt(bytes) {
	return BigInt("0x" + toHex(bytes));
}

export function randomBytes(count) {
	const buf = new Uint8Array(count);
	getRandomValues(buf);
	return buf;
}

export function randomBigInt(min, max) {
	if (max <= min) throw new Error("randomBigInt: max must be > min");
	const range = max - min;
	const byteLength = Math.ceil(range.toString(16).length / 2);
	const extraBytes = 8;
	const totalBytes = byteLength + extraBytes;

	while (true) {
		const bytes = randomBytes(totalBytes);
		const candidate = bytesToBigInt(bytes) % range;
		const limit =
			2n ** BigInt(totalBytes * 8) - (2n ** BigInt(totalBytes * 8) % range);
		if (bytesToBigInt(bytes) < limit) {
			return min + candidate;
		}
	}
}

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

export function extendedGcd(a, b) {
	if (b === 0n) return { gcd: a, x: 1n, y: 0n };
	const { gcd, x, y } = extendedGcd(b, a % b);
	return { gcd, x: y, y: x - (a / b) * y };
}

export function modInverse(a, m) {
	const { gcd, x } = extendedGcd(((a % m) + m) % m, m);
	if (gcd !== 1n) throw new Error("modInverse: no inverse (gcd !== 1)");
	return ((x % m) + m) % m;
}

export function constantTimeEqual(a, b) {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
}

export function xorBytes(a, b) {
	if (a.length !== b.length)
		throw new Error(`xorBytes: length mismatch (${a.length} vs ${b.length})`);
	const result = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) {
		result[i] = a[i] ^ b[i];
	}
	return result;
}

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

export function i2osp(n, length) {
	return bigIntToBytes(n, length);
}

export function os2ip(bytes) {
	return bytesToBigInt(bytes);
}
