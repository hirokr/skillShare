import "dotenv/config";
import http from "http";
import { Server as SocketServer } from "socket.io";
import app from "./app.js";
import { registerMessageSocket } from "./socket/messageSocket.js";

const PORT = process.env.PORT || 5000;
const allowedOrigin = process.env.CLIENT_ORIGIN || "http://localhost:3000";

const server = http.createServer(app);
const io = new SocketServer(server, {
	cors: {
		origin: allowedOrigin,
		credentials: true,
	},
});

registerMessageSocket(io);

server.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
