"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiGet } from "@/lib/api";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

type ConversationSummary = {
	id: string;
	otherUser: {
		id: string;
		username: string;
		displayName: string;
		avatarUrl: string | null;
	} | null;
	lastMessageAt: string | null;
	lastMessagePreview: string | null;
	unreadCount: number;
};

export default function MessagesPage() {
	const router = useRouter();
	const [conversations, setConversations] = useState<ConversationSummary[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let isMounted = true;
		apiGet("/auth/session")
			.then(() => apiGet("/messages/conversations"))
			.then((data) => {
				if (!isMounted) return;
				const payload = data as { conversations: ConversationSummary[] };
				setConversations(payload.conversations ?? []);
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
	}, [router]);

	if (isLoading) {
		return (
			<div className='p-6'>
				<Card>
					<CardHeader>
						<CardTitle>Loading messages</CardTitle>
						<CardDescription>Decrypting your inbox...</CardDescription>
					</CardHeader>
				</Card>
			</div>
		);
	}

	return (
		<div className='space-y-6 p-6'>
			<div className='flex items-center justify-between'>
				<div>
					<h2 className='text-lg font-semibold'>Messages</h2>
					<p className='text-sm text-muted-foreground'>
						Encrypted conversations
					</p>
				</div>
				<Button asChild variant='outline'>
					<Link href='/feed'>Back to feed</Link>
				</Button>
			</div>

			{error ? (
				<Card>
					<CardHeader>
						<CardTitle>Could not load messages</CardTitle>
						<CardDescription>{error}</CardDescription>
					</CardHeader>
				</Card>
			) : null}

			{conversations.length === 0 ? (
				<Card>
					<CardHeader>
						<CardTitle>No conversations yet</CardTitle>
						<CardDescription>
							Visit a profile to start chatting.
						</CardDescription>
					</CardHeader>
				</Card>
			) : (
				<div className='grid gap-4'>
					{conversations.map((conversation) => {
						const name =
							conversation.otherUser?.displayName ||
							conversation.otherUser?.username ||
							"Unknown user";
						const initials = name
							.split(" ")
							.map((part) => part[0])
							.join("")
							.slice(0, 2)
							.toUpperCase();

						return (
							<Card key={conversation.id}>
								<CardHeader className='flex flex-row items-center justify-between'>
									<div className='flex items-center gap-3'>
										<Avatar>
											<AvatarImage
												src={conversation.otherUser?.avatarUrl ?? undefined}
											/>
											<AvatarFallback>{initials}</AvatarFallback>
										</Avatar>
										<div>
											<CardTitle className='text-base'>{name}</CardTitle>
											<CardDescription>
												{conversation.lastMessagePreview ?? "No preview"}
											</CardDescription>
										</div>
									</div>
									<Button asChild size='sm'>
										<Link href={`/messages/${conversation.id}`}>Open</Link>
									</Button>
								</CardHeader>
								<CardContent className='flex items-center justify-between text-sm'>
									<span className='text-muted-foreground'>
										Last active: {conversation.lastMessageAt ?? "Never"}
									</span>
									{conversation.unreadCount > 0 ? (
										<span className='rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground'>
											{conversation.unreadCount} new
										</span>
									) : null}
								</CardContent>
							</Card>
						);
					})}
				</div>
			)}
		</div>
	);
}
