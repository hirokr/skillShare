/**
 * socket/messageSocket.js
 * Socket.IO handlers for encrypted messaging.
 */

import { verifyJwt } from "../utils/jwt.js";
import { Conversation } from "../models/index.js";
import { createEncryptedMessage } from "../services/messageService.js";

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function getCookieToken(cookieHeader, name) {
	if (!cookieHeader) return null;
	const parts = cookieHeader.split(";");
	for (const part of parts) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) {
			return rest.join("=") || null;
		}
	}
	return null;
}

export function registerMessageSocket(io) {
	io.use((socket, next) => {
		try {
			const cookieToken = getCookieToken(
				socket.handshake.headers?.cookie,
				"accessToken",
			);
			const authHeader = socket.handshake.headers?.authorization || "";
			const headerToken = authHeader.startsWith("Bearer ")
				? authHeader.slice(7)
				: null;
			const token = cookieToken || headerToken;

			if (!token) {
				return next(new Error("Missing token"));
			}

			const { valid, payload } = verifyJwt(token, requireEnv("JWT_SECRET"));
			if (!valid || !payload?.userId) {
				return next(new Error("Invalid token"));
			}

			socket.data.userId = payload.userId;
			socket.data.role = payload.role || "user";
			return next();
		} catch (error) {
			return next(new Error("Socket auth failed"));
		}
	});

	io.on("connection", (socket) => {
		const userId = socket.data.userId;
		if (userId) {
			socket.join(userId);
		}

		socket.on("send_message", async (payload, ack) => {
			try {
				const { conversationId, content } = payload || {};
				if (!conversationId || !content) {
					throw new Error("Missing conversationId or content");
				}

				const conversation = await Conversation.findById(conversationId);
				if (!conversation) {
					throw new Error("Conversation not found");
				}

				const isParticipant = conversation.participants.some(
					(id) => id.toString() === userId,
				);
				if (!isParticipant) {
					throw new Error("Forbidden");
				}

				const recipientId = conversation.participants.find(
					(id) => id.toString() !== userId,
				);
				if (!recipientId) {
					throw new Error("Invalid conversation");
				}

				const { payloadForSender, payloadForRecipient } =
					await createEncryptedMessage({
						conversationId: conversation._id,
						senderId: userId,
						recipientId,
						content,
					});

				io.to(userId).emit("message_sent", payloadForSender);
				io.to(recipientId.toString()).emit(
					"message_received",
					payloadForRecipient,
				);

				if (typeof ack === "function") {
					ack({ ok: true, message: payloadForSender });
				}
			} catch (error) {
				if (typeof ack === "function") {
					ack({
						ok: false,
						message: error instanceof Error ? error.message : "Send failed",
					});
				}
			}
		});
	});
}
