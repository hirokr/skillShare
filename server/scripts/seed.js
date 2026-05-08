/**
 * scripts/seed.js
 *
 * Database seed script — uses the actual project crypto stack.
 * Run: node scripts/seed.js
 *
 * Credentials created:
 *   ADMIN  → email: admin@skillshare.dev   password: Admin@123456
 *   USER 1 → email: alice@example.com      password: Alice@123456
 *   USER 2 → email: bob@example.com        password: Bob@123456
 *   USER 3 → email: carol@example.com      password: Carol@123456
 */

import "dotenv/config";
import mongoose from "mongoose";

// ── Models ────────────────────────────────────────────────────────────────────
import User from "../models/User.js";
import Profile from "../models/Profile.js";
import Post from "../models/Post.js";
import Comment from "../models/Comment.js";
import { Conversation, Message } from "../models/Message.js";
import KeyStore from "../models/KeyStore.js";

// ── Crypto ────────────────────────────────────────────────────────────────────
import * as RSA from "../crpyto/rsa.js";
import * as ECC from "../crpyto/ecc.js";
import { generateSalt, hashPassword, hashField } from "../crpyto/hash.js";
import { sign } from "../crpyto/hmac.js";

// ── Env ───────────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;
const HMAC_KEY  = process.env.HMAC_SERVER_KEY;
const SERVER_RSA_PUB  = process.env.SERVER_RSA_PUBLIC_KEY;
const SERVER_RSA_PRIV = process.env.SERVER_RSA_PRIVATE_KEY;
const SERVER_ECC_PUB  = process.env.SERVER_ECC_PUBLIC_KEY;

if (!MONGO_URI || !HMAC_KEY || !SERVER_RSA_PUB || !SERVER_RSA_PRIV || !SERVER_ECC_PUB) {
  console.error("❌  Missing required env vars. Check your .env file.");
  process.exit(1);
}

const serverRsaPub  = RSA.deserializePublicKey(SERVER_RSA_PUB);
const serverRsaPriv = RSA.deserializePrivateKey(SERVER_RSA_PRIV);
const serverEccPub  = ECC.deserializePublicKey(SERVER_ECC_PUB);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Register-flow: build a fully-encrypted User + Profile + two KeyStore rows */
async function createUser({ username, email, password, contact, role, displayName, bio, location, website, occupation }) {
  // ── Key pairs ──────────────────────────────────────────────────────────────
  const rsaPair = RSA.generateKeyPair();
  const eccPair = ECC.generateKeyPair();

  const rsaPubSer  = RSA.serializePublicKey(rsaPair.publicKey);
  const rsaPrivSer = RSA.serializePrivateKey(rsaPair.privateKey);
  const eccPubSer  = ECC.serializePublicKey(eccPair.publicKey);
  const eccPrivSer = ECC.serializePrivateKey(eccPair.privateKey, eccPair.publicKey);

  // Encrypt private keys with server RSA master key (keys are large → chunk)
  const encRsaPriv = JSON.stringify(RSA.chunkEncrypt(rsaPrivSer, serverRsaPub));
  const encEccPriv = JSON.stringify(RSA.chunkEncrypt(eccPrivSer, serverRsaPub));

  // ── Password ───────────────────────────────────────────────────────────────
  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);

  // ── Identity encryption (ECC) ──────────────────────────────────────────────
  const encUsername = ECC.encrypt(username, serverEccPub);
  const encEmail    = ECC.encrypt(email,    serverEccPub);
  const encContact  = contact ? ECC.encrypt(contact, serverEccPub) : null;

  // ── Lookup hashes ──────────────────────────────────────────────────────────
  const usernameHash = hashField(username, HMAC_KEY);
  const emailHash    = hashField(email,    HMAC_KEY);

  // ── User HMAC ─────────────────────────────────────────────────────────────
  const userHmac = sign(
    [encUsername, encEmail, encContact ?? ""],
    HMAC_KEY,
  );

  // ── Save User ─────────────────────────────────────────────────────────────
  const user = await User.create({
    encryptedUsername:    encUsername,
    encryptedEmail:       encEmail,
    encryptedContact:     encContact,
    usernameHash,
    emailHash,
    passwordHash,
    passwordSalt:         salt,
    publicKey:            rsaPubSer,
    encryptedPrivateKey:  encRsaPriv,
    eccPublicKey:         eccPubSer,
    encryptedEccPrivateKey: encEccPriv,
    hmacSignature:        userHmac,
    role: role ?? "user",
    twoFactorEnabled:     false,
  });

  // ── KeyStore: RSA ──────────────────────────────────────────────────────────
  const rsaKsHmac = sign(
    [rsaPubSer, encRsaPriv, user._id.toString(), "1", "RSA"],
    HMAC_KEY,
  );
  await KeyStore.create({
    user:               user._id,
    algorithm:          "RSA",
    version:            1,
    publicKey:          rsaPubSer,
    encryptedPrivateKey: encRsaPriv,
    keySize:            2048,
    status:             "active",
    expiresAt:          new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    hmacSignature:      rsaKsHmac,
  });

  // ── KeyStore: ECC ──────────────────────────────────────────────────────────
  const eccKsHmac = sign(
    [eccPubSer, encEccPriv, user._id.toString(), "1", "ECC"],
    HMAC_KEY,
  );
  await KeyStore.create({
    user:               user._id,
    algorithm:          "ECC",
    version:            1,
    publicKey:          eccPubSer,
    encryptedPrivateKey: encEccPriv,
    keySize:            256,
    curve:              "secp256k1",
    status:             "active",
    expiresAt:          new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    hmacSignature:      eccKsHmac,
  });

  // ── Profile ────────────────────────────────────────────────────────────────
  const encBio        = bio        ? ECC.encrypt(bio,        serverEccPub) : null;
  const encLocation   = location   ? ECC.encrypt(location,   serverEccPub) : null;
  const encWebsite    = website    ? ECC.encrypt(website,    serverEccPub) : null;
  const encOccupation = occupation ? ECC.encrypt(occupation, serverEccPub) : null;

  const profileHmac = sign(
    [encBio ?? "", encLocation ?? "", encWebsite ?? "", user._id.toString()],
    HMAC_KEY,
  );

  await Profile.create({
    user:                user._id,
    displayName,
    encryptedBio:        encBio,
    encryptedLocation:   encLocation,
    encryptedWebsite:    encWebsite,
    encryptedOccupation: encOccupation,
    hmacSignature:       profileHmac,
  });

  console.log(`  ✅  Created ${role ?? "user"}: ${username} <${email}>`);
  return { user, rsaPair, eccPair };
}

/** Create an encrypted post */
async function createPost({ authorId, title, content, category, tags, status }) {
  const encTitle   = RSA.encrypt(title.slice(0, 120), serverRsaPub);
  const encContent = RSA.encrypt(content.slice(0, 120), serverRsaPub);
  const chunks     = content.length > 120 ? RSA.chunkEncrypt(content, serverRsaPub) : [];

  // Save first with a placeholder HMAC, then recompute with real createdAt
  const post = await Post.create({
    author:           authorId,
    encryptedTitle:   encTitle,
    encryptedContent: encContent,
    encryptedChunks:  chunks,
    category:         category ?? "need",
    tags:             tags ?? [],
    status:           status ?? "open",
    hmacSignature:    "placeholder",
  });

  // Recompute HMAC with the real createdAt (same as createPost controller does)
  const hmac = sign(
    [encTitle, encContent, authorId.toString(), post.createdAt.toISOString()],
    HMAC_KEY,
  );
  post.hmacSignature = hmac;
  await post.save();
  return post;
}

/** Create an encrypted comment */
async function createComment({ postId, authorId, content, parentCommentId }) {
  const encContent = RSA.encrypt(content.slice(0, 120), serverRsaPub);
  const chunks     = content.length > 120 ? RSA.chunkEncrypt(content, serverRsaPub) : [];

  const comment = await Comment.create({
    post:             postId,
    author:           authorId,
    parentComment:    parentCommentId ?? null,
    encryptedContent: encContent,
    encryptedChunks:  chunks,
    hmacSignature:    "placeholder",
  });

  // Recompute HMAC with real createdAt (matches commentController verify logic)
  const hmac = sign(
    [encContent, authorId.toString(), postId.toString(), comment.createdAt.toISOString()],
    HMAC_KEY,
  );
  comment.hmacSignature = hmac;
  await comment.save();
  return comment;
}

/** Create a conversation + messages between two users */
async function createConversation(senderInfo, recipientInfo, messages) {
  const sid = senderInfo.user._id;
  const rid = recipientInfo.user._id;
  const pKey = [sid.toString(), rid.toString()].sort().join(":");

  const conv = await Conversation.create({
    participants:    [sid, rid],
    participantsKey: pKey,
    lastMessageAt:   new Date(),
    unreadCount: [
      { userId: sid, count: 0 },
      { userId: rid, count: 1 },
    ],
  });

  for (const text of messages) {
    // Double-encrypt: once for sender, once for recipient
    const encForSender    = RSA.encrypt(text.slice(0, 120), senderInfo.rsaPair.publicKey);
    const encForRecipient = RSA.encrypt(text.slice(0, 120), recipientInfo.rsaPair.publicKey);
    const ts = new Date().toISOString();
    const hmac = sign(
      [encForRecipient, sid.toString(), conv._id.toString(), ts],
      HMAC_KEY,
    );

    await Message.create({
      conversation:        conv._id,
      sender:              sid,
      recipient:           rid,
      encryptedForSender:    encForSender,
      encryptedForRecipient: encForRecipient,
      hmacSignature:         hmac,
      status:                "delivered",
    });
  }

  return conv;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function seed() {
  console.log("\n🌱  Connecting to MongoDB …");
  await mongoose.connect(MONGO_URI);
  console.log("   Connected.\n");

  // ── Wipe existing data ─────────────────────────────────────────────────────
  await Promise.all([
    User.deleteMany({}),
    Profile.deleteMany({}),
    Post.deleteMany({}),
    Comment.deleteMany({}),
    Conversation.deleteMany({}),
    Message.deleteMany({}),
    KeyStore.deleteMany({}),
  ]);
  console.log("🗑️   Cleared all collections.\n");

  // ── Create users ───────────────────────────────────────────────────────────
  console.log("👤  Creating users …");
  const adminInfo = await createUser({
    username:    "admin",
    email:       "admin@skillshare.dev",
    password:    "Admin@123456",
    contact:     "+1-000-000-0000",
    role:        "admin",
    displayName: "Admin",
    bio:         "Platform administrator.",
    location:    "Server Room",
    website:     "https://skillshare.dev",
    occupation:  "Administrator",
  });

  const aliceInfo = await createUser({
    username:    "alice",
    email:       "alice@example.com",
    password:    "Alice@123456",
    contact:     "+1-111-111-1111",
    role:        "user",
    displayName: "Alice Johnson",
    bio:         "Full-stack developer looking for design help.",
    location:    "New York, USA",
    website:     "https://alice.dev",
    occupation:  "Software Engineer",
  });

  const bobInfo = await createUser({
    username:    "bob",
    email:       "bob@example.com",
    password:    "Bob@123456",
    contact:     "+1-222-222-2222",
    role:        "user",
    displayName: "Bob Smith",
    bio:         "UI/UX designer offering freelance services.",
    location:    "San Francisco, USA",
    website:     "https://bobdesigns.io",
    occupation:  "UX Designer",
  });

  const carolInfo = await createUser({
    username:    "carol",
    email:       "carol@example.com",
    password:    "Carol@123456",
    contact:     null,
    role:        "user",
    displayName: "Carol White",
    bio:         "Data scientist & ML enthusiast.",
    location:    "London, UK",
    website:     null,
    occupation:  "Data Scientist",
  });

  // ── Social graph ───────────────────────────────────────────────────────────
  console.log("\n🔗  Building follow graph …");
  await User.findByIdAndUpdate(aliceInfo.user._id, {
    $push: { following: bobInfo.user._id },
    $inc:  {},
  });
  await User.findByIdAndUpdate(bobInfo.user._id, {
    $push: { followers: aliceInfo.user._id },
  });
  await User.findByIdAndUpdate(carolInfo.user._id, {
    $push: { following: aliceInfo.user._id },
  });
  await User.findByIdAndUpdate(aliceInfo.user._id, {
    $push: { followers: carolInfo.user._id },
  });

  // ── Posts ──────────────────────────────────────────────────────────────────
  console.log("\n📝  Creating posts …");

  const post1 = await createPost({
    authorId: aliceInfo.user._id,
    title:    "Need a logo designer for my SaaS product",
    content:  "Looking for a talented designer to create a modern logo for my startup. Budget is flexible for the right candidate. Please share your portfolio.",
    category: "need",
    tags:     ["design", "logo", "startup", "paid"],
    status:   "open",
  });

  const post2 = await createPost({
    authorId: bobInfo.user._id,
    title:    "Offering free UI audits for open-source projects",
    content:  "I am a UX designer with 5 years of experience. Willing to do free UI/UX audits for open-source tools. DM me with your project link.",
    category: "offer",
    tags:     ["design", "ux", "free", "open-source"],
    status:   "open",
  });

  const post3 = await createPost({
    authorId: carolInfo.user._id,
    title:    "Question: best approach for encrypted message storage?",
    content:  "Working on a project that requires end-to-end encryption for stored messages. Should I use RSA double-encryption or a hybrid scheme? Any recommendations?",
    category: "question",
    tags:     ["encryption", "security", "database"],
    status:   "open",
  });

  const post4 = await createPost({
    authorId: aliceInfo.user._id,
    title:    "Hosting a virtual hackathon — teams welcome!",
    content:  "Organizing a 48-hour online hackathon focused on privacy-first applications. Prize pool: $2000. Register before May 15.",
    category: "event",
    tags:     ["hackathon", "event", "privacy", "coding"],
    status:   "open",
  });

  const post5 = await createPost({
    authorId: adminInfo.user._id,
    title:    "Platform maintenance notice — May 10",
    content:  "Scheduled downtime on May 10 from 02:00–04:00 UTC for database migration. No data will be lost. Apologies for the inconvenience.",
    category: "other",
    tags:     ["maintenance", "announcement"],
    status:   "open",
  });

  console.log(`   Created 5 posts.`);

  // ── Likes ──────────────────────────────────────────────────────────────────
  await Post.findByIdAndUpdate(post1._id, {
    $addToSet: { likes: bobInfo.user._id },
    $inc: { likeCount: 1 },
  });
  await Post.findByIdAndUpdate(post2._id, {
    $addToSet: { likes: aliceInfo.user._id },
    $inc: { likeCount: 1 },
  });
  await Post.findByIdAndUpdate(post3._id, {
    $addToSet: { likes: aliceInfo.user._id },
    $inc: { likeCount: 1 },
  });
  await Post.findByIdAndUpdate(post3._id, {
    $addToSet: { likes: bobInfo.user._id },
    $inc: { likeCount: 1 },
  });

  // ── Comments ───────────────────────────────────────────────────────────────
  console.log("\n💬  Creating comments …");

  const c1 = await createComment({
    postId:   post1._id,
    authorId: bobInfo.user._id,
    content:  "Hi Alice! I would love to help. I have designed logos for 3 startups. Sending you a DM.",
  });

  const c2 = await createComment({
    postId:   post1._id,
    authorId: carolInfo.user._id,
    content:  "Check out Dribbble — lots of great designers there. Good luck!",
  });

  // Reply to c1
  await createComment({
    postId:          post1._id,
    authorId:        aliceInfo.user._id,
    content:         "Thanks Bob! Looking forward to seeing your work.",
    parentCommentId: c1._id,
  });

  await createComment({
    postId:   post2._id,
    authorId: aliceInfo.user._id,
    content:  "This is amazing! I would love an audit for my open-source CLI tool. DMing you now.",
  });

  await createComment({
    postId:   post3._id,
    authorId: aliceInfo.user._id,
    content:  "We use RSA double-encryption in our current project. Each party gets their own encrypted copy. Works great!",
  });

  await createComment({
    postId:   post3._id,
    authorId: adminInfo.user._id,
    content:  "Hybrid schemes with a session key are also valid. Depends on whether the server needs to read the messages or not.",
  });

  // Update comment counts on posts
  await Post.findByIdAndUpdate(post1._id, { commentCount: 3 });
  await Post.findByIdAndUpdate(post2._id, { commentCount: 1 });
  await Post.findByIdAndUpdate(post3._id, { commentCount: 2 });

  console.log(`   Created 6 comments.`);

  // ── Conversations & Messages ───────────────────────────────────────────────
  console.log("\n✉️   Creating conversations & messages …");

  await createConversation(aliceInfo, bobInfo, [
    "Hey Bob! Saw your portfolio — your work is stunning.",
    "Would you be available for a 30-min call this week?",
  ]);

  await createConversation(carolInfo, aliceInfo, [
    "Alice, are you participating in the hackathon?",
  ]);

  await createConversation(adminInfo, aliceInfo, [
    "Hi Alice, just a heads-up about the upcoming maintenance window.",
  ]);

  console.log(`   Created 3 conversations with messages.`);

  // ── Soft-delete one post (admin moderation demo) ───────────────────────────
  await Post.findByIdAndUpdate(post5._id, {
    isDeleted: true,
    deletedBy: adminInfo.user._id,
    deletedAt: new Date(),
  });
  console.log("\n🗂️   Soft-deleted post5 (admin moderation demo).");

  // ── Done ───────────────────────────────────────────────────────────────────
  await mongoose.disconnect();

  console.log(`
╔══════════════════════════════════════════════════════╗
║               ✅  SEED COMPLETE                      ║
╠══════════════════════════════════════════════════════╣
║  ADMIN                                               ║
║    Email    : admin@skillshare.dev                   ║
║    Password : Admin@123456                           ║
╠══════════════════════════════════════════════════════╣
║  USER 1 — Alice                                      ║
║    Email    : alice@example.com                      ║
║    Password : Alice@123456                           ║
╠══════════════════════════════════════════════════════╣
║  USER 2 — Bob                                        ║
║    Email    : bob@example.com                        ║
║    Password : Bob@123456                             ║
╠══════════════════════════════════════════════════════╣
║  USER 3 — Carol                                      ║
║    Email    : carol@example.com                      ║
║    Password : Carol@123456                           ║
╚══════════════════════════════════════════════════════╝
`);
}

seed().catch((err) => {
  console.error("❌  Seed failed:", err);
  mongoose.disconnect();
  process.exit(1);
});
