"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { apiGet } from "@/lib/api";
import { getSocket } from "@/app/lib/socket";
import rsa from "@/app/lib/crypto/rsa";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

type MessageItem = {
	id: string;
	conversationId: string;
	senderId: string;
	recipientId: string;
	encrypted: string;
	chunks: string[];
	createdAt: string;
	status: string;
	isMine?: boolean;
};

type ConversationPayload = {
	conversationId: string;
	messages: MessageItem[];
};

type KeysPayload = {
	userId: string;
	rsaPrivateKey: string;
};

export default function ConversationPage() {
	const router = useRouter();
	const params = useParams();
	const conversationIdParam = params?.conversationId;
	const conversationId =
		typeof conversationIdParam === "string"
			? conversationIdParam
			: Array.isArray(conversationIdParam)
				? conversationIdParam[0]
				: "";

	const [messages, setMessages] = useState<MessageItem[]>([]);
	const [input, setInput] = useState("");
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [privateKey, setPrivateKey] = useState<string | null>(null);
	const [currentUserId, setCurrentUserId] = useState<string | null>(null);
	const endRef = useRef<HTMLDivElement | null>(null);

	useEffect(() => {
		let isMounted = true;
		if (!conversationId) return;

		Promise.resolve()
			.then(() => apiGet("/auth/session"))
			.then(() => apiGet("/auth/keys"))
			.then((data) => {
				if (!isMounted) return;
				const keys = data as KeysPayload;
				setPrivateKey(keys.rsaPrivateKey ?? null);
				setCurrentUserId(keys.userId ?? null);
			})
			.then(() => apiGet(`/messages/${conversationId}?limit=50`))
			.then((data) => {
				if (!isMounted) return;
				const payload = data as ConversationPayload;
				setMessages(payload.messages ?? []);
			})
			.catch(() => {
				if (!isMounted) return;
				router.replace("/auth/login");
			})
			.finally(() => {
				if (isMounted) setIsLoading(false);
			});

		return () => {
			isMounted = false;
		};
	}, [conversationId, router]);

	useEffect(() => {
		const socket = getSocket();
		socket.connect();

		function handleIncoming(message: MessageItem) {
			if (message.conversationId !== conversationId) return;
			setMessages((prev) => [
				...prev,
				{
					...message,
					isMine: message.senderId === currentUserId,
				},
			]);
		}

		socket.on("message_received", handleIncoming);
		socket.on("message_sent", handleIncoming);

		return () => {
			socket.off("message_received", handleIncoming);
			socket.off("message_sent", handleIncoming);
			socket.disconnect();
		};
	}, [conversationId, currentUserId]);

	useEffect(() => {
		endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
	}, [messages]);

	const rsaPrivateKey = useMemo(() => {
		if (!privateKey) return null;
		try {
			return rsa.deserializePrivateKey(privateKey);
		} catch {
			return null;
		}
	}, [privateKey]);

	const displayMessages = useMemo(() => {
		if (!rsaPrivateKey) {
			return messages.map((message) => ({ ...message, text: "" }));
		}
		return messages.map((message) => {
			const chunks = [message.encrypted, ...(message.chunks ?? [])];
			let text = "";
			try {
				text = rsa.chunkDecrypt(chunks, rsaPrivateKey);
			} catch {
				text = "[Decryption failed]";
			}
			return { ...message, text };
		});
	}, [messages, rsaPrivateKey]);

	async function handleSend(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!input.trim()) return;
		setError(null);
		const socket = getSocket();

		socket.emit(
			"send_message",
			{ conversationId, content: input.trim() },
			(response: { ok: boolean; message?: string }) => {
				if (!response?.ok) {
					setError(response?.message || "Failed to send message");
				}
			},
		);

		setInput("");
	}

	if (isLoading) {
		return (
			<div className='p-6'>
				<Card>
					<CardHeader>
						<CardTitle>Loading conversation</CardTitle>
						<CardDescription>Decrypting messages...</CardDescription>
					</CardHeader>
				</Card>
			</div>
		);
	}

	return (
		<div className='space-y-6 p-6'>
			<div className='flex items-center justify-between'>
				<div>
					<h2 className='text-lg font-semibold'>Conversation</h2>
					<p className='text-sm text-muted-foreground'>
						Messages stay encrypted in storage and transit.
					</p>
				</div>
				<Button asChild variant='outline'>
					<Link href='/messages'>Back to inbox</Link>
				</Button>
			</div>

			{error ? (
				<Card>
					<CardHeader>
						<CardTitle>Message error</CardTitle>
						<CardDescription>{error}</CardDescription>
					</CardHeader>
				</Card>
			) : null}

			<Card className='min-h-[360px]'>
				<CardContent className='space-y-4 py-4'>
					{displayMessages.length === 0 ? (
						<p className='text-sm text-muted-foreground'>No messages yet.</p>
					) : (
						displayMessages.map((message) => (
							<div
								key={message.id}
								className={`flex ${message.isMine ? "justify-end" : "justify-start"}`}
							>
								<div
									className={`max-w-[70%] rounded-lg px-3 py-2 text-sm ${
										message.isMine
											? "bg-primary text-primary-foreground"
											: "bg-muted"
									}`}
								>
									<p>{message.text || "Decrypting..."}</p>
									<p className='mt-1 text-[11px] opacity-70'>
										{message.createdAt}
									</p>
								</div>
							</div>
						))
					)}
					<div ref={endRef} />
				</CardContent>
			</Card>

			<form onSubmit={handleSend} className='space-y-3'>
				<Textarea
					value={input}
					onChange={(event) => setInput(event.target.value)}
					placeholder='Type a secure message...'
					rows={3}
					required
				/>
				<div className='flex justify-end'>
					<Button type='submit'>Send</Button>
				</div>
			</form>
		</div>
	);
}
