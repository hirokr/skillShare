import "dotenv/config";
import mongoose from "mongoose";
import Profile from "../models/Profile.js";
import { sign as signMac } from "../crpyto/hmac.js";

function requireEnv(name) {
	if (!process.env[name]) {
		throw new Error(`Missing required env: ${name}`);
	}
	return process.env[name];
}

function buildProfileMac(profile, hmacKey) {
	return signMac(
		[
			profile.encryptedBio,
			profile.encryptedSkills,
			profile.encryptedLocation,
			profile.encryptedWebsite,
			profile.encryptedOccupation,
			profile.user?.toString(),
		],
		hmacKey,
	);
}

async function run() {
	const mongoUri = requireEnv("MONGO_URI");
	const hmacKey = requireEnv("HMAC_SERVER_KEY");

	await mongoose.connect(mongoUri);

	let scanned = 0;
	let updated = 0;

	const cursor = Profile.find().cursor();
	for await (const profile of cursor) {
		scanned += 1;
		const nextSignature = buildProfileMac(profile, hmacKey);
		if (nextSignature === profile.hmacSignature) {
			continue;
		}
		await Profile.updateOne(
			{ _id: profile._id },
			{ $set: { hmacSignature: nextSignature } },
		);
		updated += 1;
	}

	await mongoose.disconnect();
	console.log(`Profile MACs updated: ${updated}/${scanned}`);
}

run().catch((error) => {
	console.error("Profile MAC re-sign failed");
	console.error(error?.message || error);
	process.exitCode = 1;
});
