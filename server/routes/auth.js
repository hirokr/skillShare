/**
 * routes/auth.js
 * Auth endpoints including 2FA setup, confirm, verify (login step), and disable.
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
	keys,
	setup2FA,
	confirm2FA,
	verify2FA,
	disable2FA,
	get2FAStatus,
} from "../controllers/authController.js";
import authenticate from "../middlewares/authenticate.js";

const router = express.Router();

// Core auth
router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.get("/me", authenticate, me);
router.get("/session", authenticate, session);
router.get("/keys", authenticate, keys);
router.patch("/password", authenticate, changePassword);

// 2FA management (requires full session)
router.get("/2fa/status", authenticate, get2FAStatus);
router.post("/2fa/setup", authenticate, setup2FA);
router.post("/2fa/confirm", authenticate, confirm2FA);
router.post("/2fa/disable", authenticate, disable2FA);

// 2FA login second step (public — guarded by short-lived pendingToken)
router.post("/2fa/verify", verify2FA);

export default router;