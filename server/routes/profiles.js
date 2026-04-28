/**
 * routes/profiles.js
 * Public profile routes.
 */

import express from "express";
import { getPublicProfile } from "../controllers/profileController.js";

const router = express.Router();

router.get("/:username", getPublicProfile);

export default router;
