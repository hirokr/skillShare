/**
 * routes/posts.js
 * Post creation and feed endpoints.
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import {
	createPost,
	getFeed,
	updatePost,
	deletePost,
} from "../controllers/postController.js";

const router = express.Router();

router.get("/", authenticate, getFeed);
router.post("/", authenticate, createPost);
router.patch("/:id", authenticate, updatePost);
router.delete("/:id", authenticate, deletePost);

export default router;
