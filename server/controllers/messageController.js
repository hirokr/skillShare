/**
 * controllers/messageController.js
 * Conversation listing and message history.
 */

import { Conversation, Message, User, Profile } from "../models/index.js";
import ecc from "../crpyto/ecc.js";
import { verify as verifyMac } from "../crpyto/hmac.js";
import {
	createEncryptedMessage,
	getOrCreateConversation,
} from "../services/messageService.js";

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

function parseConversation(conversation, userId, usersById, profilesByUserId) {
	const otherId = conversation.participants.find(
		(id) => id.toString() !== userId,
	);
	const otherUser = otherId ? usersById.get(otherId.toString()) : null;
	const otherProfile = otherId
		? profilesByUserId.get(otherId.toString())
		: null;
	const unread =
		conversation.unreadCount?.find(
			(entry) => entry.userId.toString() === userId,
		)?.count ?? 0;

	return {
		id: conversation._id.toString(),
		otherUser: otherUser
			? {
					id: otherUser._id.toString(),
					username: otherUser.username,
					displayName: otherProfile?.displayName || otherUser.username,
					avatarUrl: otherProfile?.avatarUrl || null,
				}
			: null,
		lastMessageAt: conversation.lastMessageAt
			? conversation.lastMessageAt.toISOString()
			: null,
		lastMessagePreview: conversation.lastMessagePreview
			? "Encrypted message"
			: null,
		unreadCount: unread,
	};
}

export async function getConversations(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const conversations = await Conversation.find({
			participants: userId,
			isActive: true,
		}).sort({ lastMessageAt: -1, updatedAt: -1 });

		const otherIds = conversations
			.map((conversation) =>
				conversation.participants.find((id) => id.toString() !== userId),
			)
			.filter(Boolean)
			.map((id) => id.toString());

		const [users, profiles] = await Promise.all([
			User.find({ _id: { $in: otherIds } }).select(
				"encryptedUsername encryptedEmail encryptedContact hmacSignature",
			),
			Profile.find({ user: { $in: otherIds } }).select(
				"displayName avatarUrl user",
			),
		]);

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const eccPrivateKey = getServerEccPrivateKey();

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
			usersById.set(user._id.toString(), {
				_id: user._id,
				username,
			});
		}

		const profilesByUserId = new Map();
		for (const profile of profiles) {
			profilesByUserId.set(profile.user.toString(), profile);
		}

		const list = conversations.map((conversation) =>
			parseConversation(conversation, userId, usersById, profilesByUserId),
		);

		return res.status(200).json({ conversations: list });
	} catch (error) {
		return res.status(500).json({ message: "Failed to load conversations" });
	}
}

export async function startConversation(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { recipientId } = req.body || {};
		if (!recipientId || recipientId === userId) {
			return res.status(400).json({ message: "Invalid recipient" });
		}

		const profile = await Profile.findOne({ user: recipientId }).select(
			"privacy",
		);
		if (profile && profile.privacy?.allowMessages === false) {
			return res.status(403).json({ message: "User does not accept messages" });
		}

		const conversation = await getOrCreateConversation(userId, recipientId);
		return res.status(200).json({ conversationId: conversation._id });
	} catch (error) {
		return res.status(500).json({ message: "Failed to start conversation" });
	}
}

export async function getMessages(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { conversationId } = req.params;
		const conversation = await Conversation.findById(conversationId);
		if (!conversation) {
			return res.status(404).json({ message: "Conversation not found" });
		}

		const isParticipant = conversation.participants.some(
			(id) => id.toString() === userId,
		);
		if (!isParticipant) {
			return res.status(403).json({ message: "Forbidden" });
		}

		const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 30));
		const messages = await Message.find({ conversation: conversationId })
			.sort({ createdAt: 1 })
			.limit(limit);

		const hmacKey = requireEnv("HMAC_SERVER_KEY");
		const list = messages.map((message) => {
			const macOk = verifyMac(
				[
					message.encryptedForRecipient,
					message.sender.toString(),
					message.conversation.toString(),
					message.createdAt?.toISOString(),
				],
				hmacKey,
				message.hmacSignature,
			);
			if (!macOk) {
				throw new Error("Message integrity check failed");
			}

			const isMine = message.sender.toString() === userId;
			return {
				id: message._id.toString(),
				conversationId: message.conversation.toString(),
				senderId: message.sender.toString(),
				recipientId: message.recipient.toString(),
				encrypted: isMine
					? message.encryptedForSender
					: message.encryptedForRecipient,
				chunks: isMine ? message.chunksForSender : message.chunksForRecipient,
				createdAt: message.createdAt?.toISOString(),
				status: message.status,
				isMine,
			};
		});

		return res.status(200).json({
			conversationId,
			messages: list,
		});
	} catch (error) {
		return res.status(500).json({ message: "Failed to load messages" });
	}
}

export async function sendMessage(req, res) {
	try {
		const userId = req.user?.id;
		if (!userId) {
			return res.status(401).json({ message: "Unauthorized" });
		}

		const { conversationId } = req.params;
		const { content } = req.body || {};

		const conversation = await Conversation.findById(conversationId);
		if (!conversation) {
			return res.status(404).json({ message: "Conversation not found" });
		}

		const recipientId = conversation.participants.find(
			(id) => id.toString() !== userId,
		);
		if (!recipientId) {
			return res.status(400).json({ message: "Invalid conversation" });
		}

		const { payloadForSender } = await createEncryptedMessage({
			conversationId: conversation._id,
			senderId: userId,
			recipientId,
			content,
		});

		return res.status(201).json({ message: payloadForSender });
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "Failed to send message";
		return res.status(500).json({ message });
	}
}
