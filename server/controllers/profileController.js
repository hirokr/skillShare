/**
 * controllers/profileController.js
 * Public profile read-only data.
 */

import { User, Profile, Post } from "../models/index.js";
import ecc from "../crpyto/ecc.js";
import rsa from "../crpyto/rsa.js";
import { verify as verifyMac } from "../crpyto/hmac.js";
import { hashField } from "../crpyto/hash.js";

const MAX_POST_LIMIT = 20;

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function getServerEccPrivateKey() {
	const serialized = requireEnv("SERVER_ECC_PRIVATE_KEY");
	return ecc.deserializePrivateKey(serialized);
}

function getServerRsaPrivateKey() {
	const serialized = requireEnv("SERVER_RSA_PRIVATE_KEY");
	return rsa.deserializePrivateKey(serialized);
}

function normalizeUsername(value) {
	if (value == null) return "";
	return String(value).trim().toLowerCase();
}

function decryptIfPresent(value, privateKey) {
	if (!value) return null;
	return ecc.decrypt(value, privateKey);
}

function parseSkills(value) {
	if (!value) return [];
	try {
		const parsed = JSON.parse(value);
		if (Array.isArray(parsed)) {
			return parsed.map((item) => String(item)).filter(Boolean);
		}
	} catch {
		// Fallback to comma-separated list.
	}
	return String(value)
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
}

function verifyProfileMac(profile, userId, hmacKey) {
	const fieldsWithSkills = [
		profile.encryptedBio,
		profile.encryptedSkills,
		profile.encryptedLocation,
		profile.encryptedWebsite,
		profile.encryptedOccupation,
		userId,
	];
	const fieldsLegacy = [
		profile.encryptedBio,
		profile.encryptedLocation,
		profile.encryptedWebsite,
		profile.encryptedOccupation,
		userId,
	];

	return (
		verifyMac(fieldsWithSkills, hmacKey, profile.hmacSignature) ||
		verifyMac(fieldsLegacy, hmacKey, profile.hmacSignature)
	);
}

function buildPostList(posts, rsaPrivateKey, hmacKey) {
	return posts.map((post) => {
		const macOk = verifyMac(
			[
				post.encryptedTitle,
				post.encryptedContent,
				post.author.toString(),
				post.createdAt?.toISOString(),
			],
			hmacKey,
			post.hmacSignature,
		);
		if (!macOk) {
			throw new Error("Post integrity check failed");
		}

		const title = rsa.decrypt(post.encryptedTitle, rsaPrivateKey);
		const content = rsa.chunkDecrypt(
			[post.encryptedContent, ...post.encryptedChunks],
			rsaPrivateKey,
		);

		return {
			id: post._id,
			title,
			content,
			category: post.category,
			tags: post.tags,
			createdAt: post.createdAt,
		};
	});
}

export async function getPublicProfile(req, res) {
	try {
		const username = normalizeUsername(req.params.username);
		if (!username) {
			return res.status(400).json({ message: "Username is required" });
		}

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const usernameHash = hashField(username, hmacKey);

		const user = await User.findOne({ usernameHash });
		if (!user) {
			return res.status(404).json({ message: "Profile not found" });
		}

		const profile = await Profile.findOne({ user: user._id });
		if (!profile) {
			return res.status(404).json({ message: "Profile not found" });
		}

		const userMacOk = verifyMac(
			[user.encryptedUsername, user.encryptedEmail, user.encryptedContact],
			hmacKey,
			user.hmacSignature,
		);
		if (!userMacOk) {
			return res.status(500).json({ message: "User integrity check failed" });
		}

		const profileMacOk = verifyProfileMac(
			profile,
			user._id.toString(),
			hmacKey,
		);
		if (!profileMacOk) {
			return res
				.status(500)
				.json({ message: "Profile integrity check failed" });
		}

		const eccPrivateKey = getServerEccPrivateKey();
		const rsaPrivateKey = getServerRsaPrivateKey();

		const decrypted = {
			username: decryptIfPresent(user.encryptedUsername, eccPrivateKey),
			email: decryptIfPresent(user.encryptedEmail, eccPrivateKey),
			contact: decryptIfPresent(user.encryptedContact, eccPrivateKey),
			bio: decryptIfPresent(profile.encryptedBio, eccPrivateKey),
			skills: parseSkills(
				decryptIfPresent(profile.encryptedSkills, eccPrivateKey),
			),
			location: decryptIfPresent(profile.encryptedLocation, eccPrivateKey),
			website: decryptIfPresent(profile.encryptedWebsite, eccPrivateKey),
			occupation: decryptIfPresent(profile.encryptedOccupation, eccPrivateKey),
		};

		const page = Math.max(1, Number(req.query.page) || 1);
		const limit = Math.min(
			MAX_POST_LIMIT,
			Math.max(1, Number(req.query.limit) || 6),
		);
		const skip = (page - 1) * limit;

		const posts = await Post.find({
			author: user._id,
			isDeleted: false,
			isAnonymous: false,
		})
			.sort({ createdAt: -1 })
			.skip(skip)
			.limit(limit + 1);

		const hasMore = posts.length > limit;
		const pageItems = hasMore ? posts.slice(0, limit) : posts;
		const postList = buildPostList(pageItems, rsaPrivateKey, hmacKey);

		return res.status(200).json({
			profile: {
				userId: user._id,
				username: decrypted.username,
				displayName: profile.displayName,
				avatarUrl: profile.avatarUrl,
				bannerUrl: profile.bannerUrl,
				bio: decrypted.bio,
				skills: decrypted.skills,
				occupation: decrypted.occupation,
				website: decrypted.website,
				location: profile.privacy?.showLocation ? decrypted.location : null,
				email: profile.privacy?.showEmail ? decrypted.email : null,
				contact: profile.privacy?.showContact ? decrypted.contact : null,
				allowMessages: profile.privacy?.allowMessages ?? true,
				postCount: profile.postCount,
				followerCount: profile.followerCount,
				followingCount: profile.followingCount,
			},
			posts: postList,
			hasMore,
			page,
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to load profile" });
	}
}

export default { getPublicProfile };
