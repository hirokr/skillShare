/**
 * controllers/postController.js
 * Post creation and feed retrieval.
 */

import { Post, Profile, User } from "../models/index.js";
import ecc from "../crpyto/ecc.js";
import rsa from "../crpyto/rsa.js";
import { sign as signMac, verify as verifyMac } from "../crpyto/hmac.js";

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function getServerRsaPublicKey() {
	const serialized = requireEnv("SERVER_RSA_PUBLIC_KEY");
	return rsa.deserializePublicKey(serialized);
}

function getServerRsaPrivateKey() {
	const serialized = requireEnv("SERVER_RSA_PRIVATE_KEY");
	return rsa.deserializePrivateKey(serialized);
}

function getServerEccPrivateKey() {
	const serialized = requireEnv("SERVER_ECC_PRIVATE_KEY");
	return ecc.deserializePrivateKey(serialized);
}

function buildAuthorLookup(users, profiles, hmacKey, eccPrivateKey) {
	const usersById = new Map();
	for (const user of users) {
		const macOk = verifyMac(
			[user.encryptedUsername, user.encryptedEmail, user.encryptedContact],
			hmacKey,
			user.hmacSignature,
		);
		if (!macOk) {
			throw new Error("User integrity check failed");
		}
		const username = ecc.decrypt(user.encryptedUsername, eccPrivateKey);
		usersById.set(user._id.toString(), { id: user._id.toString(), username });
	}

	const profilesByUserId = new Map();
	for (const profile of profiles) {
		profilesByUserId.set(profile.user.toString(), profile);
	}

	return { usersById, profilesByUserId };
}

function normalizeText(value, maxLen) {
	if (value == null) return "";
	const text = String(value).trim();
	if (!text) return "";
	return text.length > maxLen ? text.slice(0, maxLen) : text;
}

function parseTags(value) {
	if (!value) return [];
	return String(value)
		.split(",")
		.map((tag) => tag.trim())
		.filter(Boolean)
		.slice(0, 10);
}

export async function createPost(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { title, content, category, tags, isAnonymous } = req.body || {};
		const cleanTitle = normalizeText(title, 120);
		const cleanContent = normalizeText(content, 5000);

		if (!cleanTitle || !cleanContent) {
			return res
				.status(400)
				.json({ message: "Title and content are required" });
		}

		const allowedCategories = ["need", "offer", "question", "event", "other"];
		const safeCategory = allowedCategories.includes(category)
			? category
			: "need";
		const tagList = parseTags(tags);

		const rsaPublicKey = getServerRsaPublicKey();
		const encryptedTitle = rsa.encrypt(cleanTitle, rsaPublicKey);
		const contentChunks = rsa.chunkEncrypt(cleanContent, rsaPublicKey);
		if (!contentChunks.length) {
			return res.status(400).json({ message: "Content is too short" });
		}

		const encryptedContent = contentChunks[0];
		const encryptedChunks = contentChunks.slice(1);
		const createdAt = new Date();

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const hmacSignature = signMac(
			[encryptedTitle, encryptedContent, userId, createdAt.toISOString()],
			hmacKey,
		);

		const post = await Post.create({
			author: userId,
			encryptedTitle,
			encryptedContent,
			encryptedChunks,
			category: safeCategory,
			tags: tagList,
			isAnonymous: Boolean(isAnonymous),
			keyVersion: req.user?.keyVersion || 1,
			hmacSignature,
			createdAt,
			updatedAt: createdAt,
		});

		return res.status(201).json({
			post: {
				id: post._id,
				category: post.category,
				tags: post.tags,
				createdAt: post.createdAt,
			},
		});
	} catch (error) {
		return res.status(500).json({ message: "Post creation failed" });
	}
}

export async function getFeed(req, res) {
	try {
		const rsaPrivateKey = getServerRsaPrivateKey();
		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const page = Math.max(1, Number(req.query.page) || 1);
		const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 10));
		const skip = (page - 1) * limit;

		const posts = await Post.find({ isDeleted: false })
			.sort({ createdAt: -1 })
			.skip(skip)
			.limit(limit + 1);

		const hasMore = posts.length > limit;
		const pageItems = hasMore ? posts.slice(0, limit) : posts;

		const authorIds = Array.from(
			new Set(
				pageItems
					.filter((post) => !post.isAnonymous)
					.map((post) => post.author.toString()),
			),
		);

		let usersById = new Map();
		let profilesByUserId = new Map();
		if (authorIds.length > 0) {
			const [users, profiles] = await Promise.all([
				User.find({ _id: { $in: authorIds } }).select(
					"encryptedUsername encryptedEmail encryptedContact hmacSignature",
				),
				Profile.find({ user: { $in: authorIds } }).select(
					"displayName avatarUrl user",
				),
			]);
			const eccPrivateKey = getServerEccPrivateKey();
			({ usersById, profilesByUserId } = buildAuthorLookup(
				users,
				profiles,
				hmacKey,
				eccPrivateKey,
			));
		}

		const feed = pageItems.map((post) => {
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

			const authorId = post.author.toString();
			const authorProfile = profilesByUserId.get(authorId);
			const authorUser = usersById.get(authorId);
			const author = post.isAnonymous
				? null
				: authorUser
					? {
							id: authorId,
							username: authorUser.username,
							displayName: authorProfile?.displayName || authorUser.username,
							avatarUrl: authorProfile?.avatarUrl || null,
						}
					: null;

			return {
				id: post._id,
				title,
				content,
				category: post.category,
				tags: post.tags,
				createdAt: post.createdAt,
				author,
			};
		});

		return res.status(200).json({
			posts: feed,
			page,
			hasMore,
			currentUserId: req.user?.id || null,
			currentUserRole: req.user?.role || null,
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to load feed" });
	}
}

export async function updatePost(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const post = await Post.findById(req.params.id);
		if (!post || post.isDeleted) {
			return res.status(404).json({ message: "Post not found" });
		}

		const isOwner = post.author.toString() === userId;
		const isAdmin = req.user?.role === "admin";
		if (!isOwner && !isAdmin) {
			return res.status(403).json({ message: "Forbidden" });
		}

		const { title, content, category, tags, isAnonymous } = req.body || {};
		const cleanTitle =
			typeof title === "undefined" ? null : normalizeText(title, 120);
		const cleanContent =
			typeof content === "undefined" ? null : normalizeText(content, 5000);

		const allowedCategories = ["need", "offer", "question", "event", "other"];
		const safeCategory = allowedCategories.includes(category)
			? category
			: post.category;
		const tagList = typeof tags === "undefined" ? post.tags : parseTags(tags);

		const rsaPublicKey = getServerRsaPublicKey();
		if (cleanTitle !== null) {
			post.encryptedTitle = rsa.encrypt(cleanTitle, rsaPublicKey);
		}
		if (cleanContent !== null) {
			const contentChunks = rsa.chunkEncrypt(cleanContent, rsaPublicKey);
			if (!contentChunks.length) {
				return res.status(400).json({ message: "Content is too short" });
			}
			post.encryptedContent = contentChunks[0];
			post.encryptedChunks = contentChunks.slice(1);
		}

		post.category = safeCategory;
		post.tags = tagList;
		if (typeof isAnonymous !== "undefined") {
			post.isAnonymous = Boolean(isAnonymous);
		}
		post.keyVersion = req.user?.keyVersion || post.keyVersion;
		post.updatedAt = new Date();

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		post.hmacSignature = signMac(
			[
				post.encryptedTitle,
				post.encryptedContent,
				post.author.toString(),
				post.createdAt?.toISOString(),
			],
			hmacKey,
		);

		await post.save();

		return res.status(200).json({ message: "Post updated" });
	} catch (error) {
		return res.status(500).json({ message: "Post update failed" });
	}
}

export async function deletePost(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const post = await Post.findById(req.params.id);
		if (!post || post.isDeleted) {
			return res.status(404).json({ message: "Post not found" });
		}

		const isOwner = post.author.toString() === userId;
		const isAdmin = req.user?.role === "admin";
		if (!isOwner && !isAdmin) {
			return res.status(403).json({ message: "Forbidden" });
		}

		post.isDeleted = true;
		post.deletedBy = userId;
		post.deletedAt = new Date();
		await post.save();

		return res.status(200).json({ message: "Post deleted" });
	} catch (error) {
		return res.status(500).json({ message: "Post deletion failed" });
	}
}

export default { createPost, getFeed, updatePost, deletePost };
