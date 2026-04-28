/**
 * routes/comments.js
 * Comment endpoints.
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import {
	createComment,
	getComments,
} from "../controllers/commentController.js";

const router = express.Router();

router.get("/", authenticate, getComments);
router.post("/", authenticate, createComment);

export default router;
