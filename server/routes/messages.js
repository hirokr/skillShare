/**
 * routes/messages.js
 * Conversation and message endpoints.
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import {
	getConversations,
	startConversation,
	getMessages,
	sendMessage,
} from "../controllers/messageController.js";

const router = express.Router();

router.get("/conversations", authenticate, getConversations);
router.post("/conversations", authenticate, startConversation);
router.get("/:conversationId", authenticate, getMessages);
router.post("/:conversationId", authenticate, sendMessage);

export default router;
