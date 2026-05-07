/**
 * routes/auth.js
 * Auth endpoints including two-step verification (2FA).
 */
 
import express from "express";
import {
	register,
	login,
	verify2FA,
	setup2FA,
	confirm2FA,
	disable2FA,
	refresh,
	logout,
	me,
	changePassword,
	session,
	keys,
} from "../controllers/authController.js";
import authenticate from "../middlewares/authenticate.js";
 
const router = express.Router();
 
// Public
router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
 
// Two-step verification (step 2 — no session required, uses tempToken)
router.post("/2fa/verify", verify2FA);
 
// Authenticated — 2FA management
router.post("/2fa/setup", authenticate, setup2FA);
router.post("/2fa/confirm", authenticate, confirm2FA);
router.post("/2fa/disable", authenticate, disable2FA);
 
// Authenticated — account
router.get("/me", authenticate, me);
router.get("/session", authenticate, session);
router.get("/keys", authenticate, keys);
router.patch("/password", authenticate, changePassword);
 
export default router;
 