/**
 * routes/dashboard.js
 * Authenticated dashboard routes.
 */

import express from "express";
import authenticate from "../middlewares/authenticate.js";
import {
	getDashboard,
	updateProfile,
} from "../controllers/dashboardController.js";

const router = express.Router();

router.get("/", authenticate, getDashboard);
router.patch("/profile", authenticate, updateProfile);

export default router;
