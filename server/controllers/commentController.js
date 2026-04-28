/**
 * controllers/commentController.js
 * Comment creation and retrieval with encryption.
 */

import { Comment, Post } from "../models/index.js";
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

function normalizeText(value, maxLen) {
	if (value == null) return "";
	const text = String(value).trim();
	if (!text) return "";
	return text.length > maxLen ? text.slice(0, maxLen) : text;
}

export async function createComment(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { postId, content, parentComment } = req.body || {};
		if (!postId) {
			return res.status(400).json({ message: "Missing post id" });
		}

		const post = await Post.findById(postId);
		if (!post || post.isDeleted) {
			return res.status(404).json({ message: "Post not found" });
		}

		const cleanContent = normalizeText(content, 1000);
		if (!cleanContent) {
			return res.status(400).json({ message: "Comment is required" });
		}

		const rsaPublicKey = getServerRsaPublicKey();
		const contentChunks = rsa.chunkEncrypt(cleanContent, rsaPublicKey);
		if (!contentChunks.length) {
			return res.status(400).json({ message: "Comment is too short" });
		}

		const encryptedContent = contentChunks[0];
		const encryptedChunks = contentChunks.slice(1);

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const hmacSignature = signMac([encryptedContent, userId, postId], hmacKey);

		const comment = await Comment.create({
			post: postId,
			author: userId,
			parentComment: parentComment || null,
			encryptedContent,
			encryptedChunks,
			keyVersion: req.user?.keyVersion || 1,
			hmacSignature,
		});

		return res.status(201).json({
			comment: {
				id: comment._id,
				postId: comment.post,
				createdAt: comment.createdAt,
			},
		});
	} catch (error) {
		return res.status(500).json({ message: "Comment creation failed" });
	}
}

export async function getComments(req, res) {
	try {
		const { postId } = req.query || {};
		if (!postId) {
			return res.status(400).json({ message: "Missing post id" });
		}

		const rsaPrivateKey = getServerRsaPrivateKey();
		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 20));

		const comments = await Comment.find({
			post: postId,
			isDeleted: false,
		})
			.sort({ createdAt: 1 })
			.limit(limit);

		const list = comments.map((comment) => {
			const macOk = verifyMac(
				[
					comment.encryptedContent,
					comment.author.toString(),
					comment.post.toString(),
				],
				hmacKey,
				comment.hmacSignature,
			);
			if (!macOk) {
				throw new Error("Comment integrity check failed");
			}

			const content = rsa.chunkDecrypt(
				[comment.encryptedContent, ...comment.encryptedChunks],
				rsaPrivateKey,
			);

			return {
				id: comment._id,
				postId: comment.post,
				author: comment.author,
				content,
				createdAt: comment.createdAt,
				parentComment: comment.parentComment,
			};
		});

		return res.status(200).json({ comments: list });
	} catch (error) {
		return res.status(500).json({ message: "Failed to load comments" });
	}
}

export default { createComment, getComments };
