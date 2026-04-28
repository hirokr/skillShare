/**
 * routes/auth.js
 * Auth endpoints (no 2FA).
 */

import express from "express";
import {
	register,
	login,
	refresh,
	logout,
	me,
	changePassword,
	session,
} from "../controllers/authController.js";
import authenticate from "../middlewares/authenticate.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/me", authenticate, me);
router.get("/session", authenticate, session);
router.patch("/password", authenticate, changePassword);

export default router;
