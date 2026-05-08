/**
 * scripts/rotate-expired-keys.js
 *
 * One-shot script that connects to MongoDB, rotates all keys whose
 * `expiresAt` has passed, then disconnects.
 *
 * Run manually:
 *   node scripts/rotate-expired-keys.js
 *
 * Or schedule via cron (daily at 2 AM):
 *   0 2 * * * cd /path/to/server && node scripts/rotate-expired-keys.js >> logs/key-rotation.log 2>&1
 *
 * Add to package.json scripts:
 *   "rotate:keys": "node scripts/rotate-expired-keys.js"
 */

import "dotenv/config";
import mongoose from "mongoose";
import { checkAndRotateExpired } from "../services/keyManager.js";

function requireEnv(name) {
	if (!process.env[name]) throw new Error(`Missing required env: ${name}`);
	return process.env[name];
}

async function run() {
	const mongoUri = requireEnv("MONGO_URI");

	console.log(`[rotate-expired-keys] Starting — ${new Date().toISOString()}`);
	await mongoose.connect(mongoUri);
	console.log("[rotate-expired-keys] Connected to MongoDB");

	const { rotated, errors } = await checkAndRotateExpired();

	await mongoose.disconnect();
	console.log(`[rotate-expired-keys] Done — rotated: ${rotated}, errors: ${errors}`);

	if (errors > 0) {
		process.exitCode = 1;
	}
}

run().catch((err) => {
	console.error("[rotate-expired-keys] Fatal error:", err?.message || err);
	process.exitCode = 1;
});