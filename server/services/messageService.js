/**
 * services/messageService.js
 * Shared helpers for encrypted messaging.
 */

import { Conversation, Message, User } from "../models/index.js";
import rsa from "../crpyto/rsa.js";
import { sign as signMac } from "../crpyto/hmac.js";

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

function normalizeText(value, maxLen) {
	if (value == null) return "";
	const text = String(value).trim();
	if (!text) return "";
	return text.length > maxLen ? text.slice(0, maxLen) : text;
}

function sortedParticipants(a, b) {
	return [a, b]
		.map((id) => id.toString())
		.sort((left, right) => left.localeCompare(right));
}

export async function getOrCreateConversation(userId, recipientId) {
	const [left, right] = sortedParticipants(userId, recipientId);
	let conversation = await Conversation.findOne({
		participants: [left, right],
	});
	if (!conversation) {
		conversation = await Conversation.create({
			participants: [left, right],
			unreadCount: [
				{ userId: left, count: 0 },
				{ userId: right, count: 0 },
			],
		});
	}
	return conversation;
}

export async function createEncryptedMessage({
	conversationId,
	senderId,
	recipientId,
	content,
}) {
	const cleanContent = normalizeText(content, 2000);
	if (!cleanContent) {
		throw new Error("Message content is required");
	}

	const [sender, recipient] = await Promise.all([
		User.findById(senderId).select("publicKey keyVersion"),
		User.findById(recipientId).select("publicKey keyVersion"),
	]);

	if (!sender || !recipient) {
		throw new Error("Message participants not found");
	}

	const senderPublicKey = rsa.deserializePublicKey(sender.publicKey);
	const recipientPublicKey = rsa.deserializePublicKey(recipient.publicKey);

	const senderChunks = rsa.chunkEncrypt(cleanContent, senderPublicKey);
	const recipientChunks = rsa.chunkEncrypt(cleanContent, recipientPublicKey);

	if (!senderChunks.length || !recipientChunks.length) {
		throw new Error("Message is too short");
	}

	const encryptedForSender = senderChunks[0];
	const chunksForSender = senderChunks.slice(1);
	const encryptedForRecipient = recipientChunks[0];
	const chunksForRecipient = recipientChunks.slice(1);

	const createdAt = new Date();
	const hmacKey = requireEnv("HMAC_SERVER_KEY");
	const hmacSignature = signMac(
		[
			encryptedForRecipient,
			senderId.toString(),
			conversationId.toString(),
			createdAt.toISOString(),
		],
		hmacKey,
	);

	const message = await Message.create({
		conversation: conversationId,
		sender: senderId,
		recipient: recipientId,
		encryptedForSender,
		encryptedForRecipient,
		chunksForSender,
		chunksForRecipient,
		senderKeyVersion: sender.keyVersion || 1,
		recipientKeyVersion: recipient.keyVersion || 1,
		hmacSignature,
		createdAt,
		updatedAt: createdAt,
	});

	await Conversation.updateOne(
		{ _id: conversationId },
		{
			$set: {
				lastMessageAt: createdAt,
				lastMessagePreview: encryptedForRecipient,
			},
			$inc: {
				"unreadCount.$[entry].count": 1,
			},
		},
		{
			arrayFilters: [{ "entry.userId": recipientId }],
		},
	);

	return {
		message,
		payloadForSender: {
			id: message._id.toString(),
			conversationId: conversationId.toString(),
			senderId: senderId.toString(),
			recipientId: recipientId.toString(),
			encrypted: encryptedForSender,
			chunks: chunksForSender,
			createdAt: createdAt.toISOString(),
			status: message.status,
		},
		payloadForRecipient: {
			id: message._id.toString(),
			conversationId: conversationId.toString(),
			senderId: senderId.toString(),
			recipientId: recipientId.toString(),
			encrypted: encryptedForRecipient,
			chunks: chunksForRecipient,
			createdAt: createdAt.toISOString(),
			status: message.status,
		},
	};
}
