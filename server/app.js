import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import authRoutes from "./routes/auth.js";
import dashboardRoutes from "./routes/dashboard.js";
import postRoutes from "./routes/posts.js";
import commentRoutes from "./routes/comments.js";

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigin = process.env.CLIENT_ORIGIN || "http://localhost:3000";
app.use(
	cors({
		origin: allowedOrigin,
		credentials: true,
	}),
);
app.use(bodyParser.json());

app.get("/", (req, res) => {
	res.send("Hello World!");
});

app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);

export default app;
