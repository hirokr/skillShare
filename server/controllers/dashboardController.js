/**
 * controllers/dashboardController.js
 * Authenticated user dashboard data and profile updates.
 */

import { User, Profile } from "../models/index.js";
import ecc from "../crpyto/ecc.js";
import { sign as signMac, verify as verifyMac } from "../crpyto/hmac.js";

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function getServerEccPublicKey() {
	const serialized = requireEnv("SERVER_ECC_PUBLIC_KEY");
	return ecc.deserializePublicKey(serialized);
}

function getServerEccPrivateKey() {
	const serialized = requireEnv("SERVER_ECC_PRIVATE_KEY");
	return ecc.deserializePrivateKey(serialized);
}

function normalizeText(value, maxLen) {
	if (value == null) return null;
	const text = String(value).trim();
	if (!text) return null;
	return text.length > maxLen ? text.slice(0, maxLen) : text;
}

function decryptIfPresent(value, privateKey) {
	if (!value) return null;
	return ecc.decrypt(value, privateKey);
}

export async function getDashboard(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const [user, profile] = await Promise.all([
			User.findById(userId),
			Profile.findOne({ user: userId }),
		]);

		if (!user || !profile) {
			return res.status(404).json({ message: "Profile not found" });
		}

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const userMacOk = verifyMac(
			[user.encryptedUsername, user.encryptedEmail, user.encryptedContact],
			hmacKey,
			user.hmacSignature,
		);
		if (!userMacOk) {
			return res.status(500).json({ message: "User integrity check failed" });
		}

		const profileMacOk = verifyMac(
			[
				profile.encryptedBio,
				profile.encryptedLocation,
				profile.encryptedWebsite,
				profile.encryptedOccupation,
				userId,
			],
			hmacKey,
			profile.hmacSignature,
		);
		if (!profileMacOk) {
			return res
				.status(500)
				.json({ message: "Profile integrity check failed" });
		}

		const eccPrivateKey = getServerEccPrivateKey();

		const decrypted = {
			username: decryptIfPresent(user.encryptedUsername, eccPrivateKey),
			email: decryptIfPresent(user.encryptedEmail, eccPrivateKey),
			contact: decryptIfPresent(user.encryptedContact, eccPrivateKey),
			bio: decryptIfPresent(profile.encryptedBio, eccPrivateKey),
			location: decryptIfPresent(profile.encryptedLocation, eccPrivateKey),
			website: decryptIfPresent(profile.encryptedWebsite, eccPrivateKey),
			occupation: decryptIfPresent(profile.encryptedOccupation, eccPrivateKey),
		};

		return res.status(200).json({
			user: {
				id: user._id,
				username: decrypted.username,
				email: decrypted.email,
				contact: decrypted.contact,
				role: user.role,
				profilePictureUrl: user.profilePictureUrl,
			},
			profile: {
				displayName: profile.displayName,
				avatarUrl: profile.avatarUrl,
				bannerUrl: profile.bannerUrl,
				bio: decrypted.bio,
				location: decrypted.location,
				website: decrypted.website,
				occupation: decrypted.occupation,
				privacy: profile.privacy,
				postCount: profile.postCount,
				followerCount: profile.followerCount,
				followingCount: profile.followingCount,
			},
		});
	} catch (error) {
		return res.status(500).json({ message: "Dashboard load failed" });
	}
}

export async function updateProfile(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const profile = await Profile.findOne({ user: userId });
		if (!profile) {
			return res.status(404).json({ message: "Profile not found" });
		}

		const {
			displayName,
			avatarUrl,
			bannerUrl,
			bio,
			location,
			website,
			occupation,
			privacy,
		} = req.body || {};

		const cleanDisplayName = normalizeText(displayName, 60);
		const cleanBio = normalizeText(bio, 500);
		const cleanLocation = normalizeText(location, 120);
		const cleanWebsite = normalizeText(website, 200);
		const cleanOccupation = normalizeText(occupation, 120);

		const eccPublicKey = getServerEccPublicKey();

		if (typeof displayName !== "undefined") {
			profile.displayName = cleanDisplayName || "";
		}
		if (typeof avatarUrl !== "undefined") {
			profile.avatarUrl = normalizeText(avatarUrl, 500);
		}
		if (typeof bannerUrl !== "undefined") {
			profile.bannerUrl = normalizeText(bannerUrl, 500);
		}
		if (typeof bio !== "undefined") {
			profile.encryptedBio = cleanBio
				? ecc.encrypt(cleanBio, eccPublicKey)
				: null;
		}
		if (typeof location !== "undefined") {
			profile.encryptedLocation = cleanLocation
				? ecc.encrypt(cleanLocation, eccPublicKey)
				: null;
		}
		if (typeof website !== "undefined") {
			profile.encryptedWebsite = cleanWebsite
				? ecc.encrypt(cleanWebsite, eccPublicKey)
				: null;
		}
		if (typeof occupation !== "undefined") {
			profile.encryptedOccupation = cleanOccupation
				? ecc.encrypt(cleanOccupation, eccPublicKey)
				: null;
		}
		if (privacy && typeof privacy === "object") {
			profile.privacy = {
				...profile.privacy,
				...privacy,
			};
		}

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		profile.hmacSignature = signMac(
			[
				profile.encryptedBio,
				profile.encryptedLocation,
				profile.encryptedWebsite,
				profile.encryptedOccupation,
				userId,
			],
			hmacKey,
		);
		profile.keyVersion = req.user?.keyVersion || profile.keyVersion;
		await profile.save();

		const eccPrivateKey = getServerEccPrivateKey();
		return res.status(200).json({
			profile: {
				displayName: profile.displayName,
				avatarUrl: profile.avatarUrl,
				bannerUrl: profile.bannerUrl,
				bio: decryptIfPresent(profile.encryptedBio, eccPrivateKey),
				location: decryptIfPresent(profile.encryptedLocation, eccPrivateKey),
				website: decryptIfPresent(profile.encryptedWebsite, eccPrivateKey),
				occupation: decryptIfPresent(
					profile.encryptedOccupation,
					eccPrivateKey,
				),
				privacy: profile.privacy,
			},
		});
	} catch (error) {
		return res.status(500).json({ message: "Profile update failed" });
	}
}

export default { getDashboard, updateProfile };
