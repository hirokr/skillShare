"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useParams } from "next/navigation";
import Link from "next/link";
import { apiGet, apiPost } from "@/lib/api";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

type PublicProfile = {
	userId: string;
	username: string | null;
	displayName: string;
	avatarUrl: string | null;
	bannerUrl: string | null;
	bio: string | null;
	skills: string[];
	occupation: string | null;
	website: string | null;
	location: string | null;
	email: string | null;
	contact: string | null;
	allowMessages: boolean;
	postCount: number;
	followerCount: number;
	followingCount: number;
};

type PublicPost = {
	id: string;
	title: string;
	content: string;
	category: string;
	tags: string[];
	createdAt: string;
};

type ProfilePayload = {
	profile: PublicProfile;
	posts: PublicPost[];
	hasMore: boolean;
	page: number;
};

function formatDate(value: string) {
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) return "";
	return date.toLocaleString();
}

export default function ProfilePage() {
	const router = useRouter();
	const params = useParams();
	const usernameParam = params?.username;
	const username = useMemo(() => {
		if (typeof usernameParam === "string") return usernameParam;
		if (Array.isArray(usernameParam)) return usernameParam[0] ?? "";
		return "";
	}, [usernameParam]);

	const [profile, setProfile] = useState<PublicProfile | null>(null);
	const [posts, setPosts] = useState<PublicPost[]>([]);
	const [page, setPage] = useState(1);
	const [hasMore, setHasMore] = useState(false);
	const [isLoading, setIsLoading] = useState(true);
	const [isPaging, setIsPaging] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [isStartingChat, setIsStartingChat] = useState(false);
	const [currentUserId, setCurrentUserId] = useState<string | null>(null);

	useEffect(() => {
		let isMounted = true;
		apiGet("/auth/session")
			.then((data) => {
				if (!isMounted) return;
				const payload = data as { userId?: string };
				setCurrentUserId(payload.userId ?? null);
			})
			.catch(() => null);

		return () => {
			isMounted = false;
		};
	}, []);

	useEffect(() => {
		if (!username) return;
		let isMounted = true;
		setIsLoading(true);
		setError(null);
		apiGet(`/profiles/${encodeURIComponent(username)}?page=1&limit=6`)
			.then((data) => {
				if (!isMounted) return;
				const payload = data as ProfilePayload;
				setProfile(payload.profile);
				setPosts(payload.posts ?? []);
				setHasMore(Boolean(payload.hasMore));
				setPage(payload.page ?? 1);
			})
			.catch((err) => {
				if (!isMounted) return;
				setError(err instanceof Error ? err.message : "Failed to load profile");
			})
			.finally(() => {
				if (isMounted) setIsLoading(false);
			});

		return () => {
			isMounted = false;
		};
	}, [username]);

	async function loadPage(nextPage: number) {
		if (!username || nextPage < 1) return;
		setIsPaging(true);
		setError(null);
		try {
			const data = await apiGet(
				`/profiles/${encodeURIComponent(username)}?page=${nextPage}&limit=6`,
			);
			const payload = data as ProfilePayload;
			setProfile(payload.profile);
			setPosts(payload.posts ?? []);
			setHasMore(Boolean(payload.hasMore));
			setPage(payload.page ?? nextPage);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to load posts");
		} finally {
			setIsPaging(false);
		}
	}

	if (isLoading) {
		return (
			<div className='mx-auto w-full max-w-6xl px-8 pb-24 pt-14 sm:px-10 lg:px-16'>
				<Card>
					<CardHeader>
						<CardTitle>Loading profile</CardTitle>
						<CardDescription>Decrypting public data...</CardDescription>
					</CardHeader>
					<CardContent>
						<div className='h-4 w-40 rounded bg-muted/40 animate-pulse' />
					</CardContent>
				</Card>
			</div>
		);
	}

	if (!profile) {
		return (
			<div className='mx-auto w-full max-w-6xl px-8 pb-24 pt-14 sm:px-10 lg:px-16'>
				<Card>
					<CardHeader>
						<CardTitle>Profile unavailable</CardTitle>
						<CardDescription>{error ?? "Try again."}</CardDescription>
					</CardHeader>
				</Card>
			</div>
		);
	}

	const displayName = profile.displayName || profile.username || "User";
	const initials = displayName
		.split(" ")
		.map((part) => part[0])
		.join("")
		.slice(0, 2)
		.toUpperCase();

	return (
		<div className='mx-auto w-full max-w-6xl space-y-6 px-8 pb-24 pt-14 sm:px-10 lg:px-16'>
			<div className='flex items-center justify-between'>
				<div>
					<h2 className='text-lg font-semibold'>Public profile</h2>
					<p className='text-sm text-muted-foreground'>
						Verified, decrypted data.
					</p>
				</div>
				<div className='flex items-center gap-2'>
					<Button asChild variant='outline'>
						<Link href='/feed'>Back to feed</Link>
					</Button>
					{currentUserId && profile.userId === currentUserId ? (
						<Button asChild variant='secondary'>
							<Link href='/dashboard'>Update profile</Link>
						</Button>
					) : null}
					<Button
						disabled={!profile.allowMessages || isStartingChat}
						onClick={async () => {
							if (!profile.allowMessages) return;
							setIsStartingChat(true);
							setError(null);
							try {
								const data = await apiPost("/messages/conversations", {
									recipientId: profile.userId,
								});
								const payload = data as { conversationId: string };
								router.push(`/messages/${payload.conversationId}`);
							} catch (err) {
								setError(
									err instanceof Error
										? err.message
										: "Unable to start conversation",
								);
							} finally {
								setIsStartingChat(false);
							}
						}}
					>
						{profile.allowMessages ? "Message" : "Messages disabled"}
					</Button>
				</div>
			</div>

			<Card className='overflow-hidden'>
				<div className='relative h-32 w-full'>
					{profile.bannerUrl ? (
						<img
							src={profile.bannerUrl}
							alt='Profile banner'
							className='h-full w-full object-cover'
						/>
					) : (
						<div className='h-full w-full bg-gradient-to-r from-emerald-100 via-sky-100 to-amber-100' />
					)}
					<div className='absolute inset-0 bg-gradient-to-t from-black/30 via-transparent to-transparent' />
				</div>
				<CardContent className='-mt-6 flex flex-col gap-4 sm:flex-row sm:items-end'>
					<Avatar size='lg' className='ring-4 ring-background'>
						<AvatarImage src={profile.avatarUrl ?? undefined} />
						<AvatarFallback>{initials}</AvatarFallback>
					</Avatar>
					<div className='flex-1'>
						<h3 className='text-xl font-semibold'>{displayName}</h3>
						<p className='text-sm text-muted-foreground'>
							@{profile.username ?? username}
						</p>
					</div>
					<div className='grid grid-cols-3 gap-4 text-center text-sm'>
						<div>
							<div className='text-base font-semibold'>{profile.postCount}</div>
							<div className='text-muted-foreground'>Posts</div>
						</div>
						<div>
							<div className='text-base font-semibold'>
								{profile.followerCount}
							</div>
							<div className='text-muted-foreground'>Followers</div>
						</div>
						<div>
							<div className='text-base font-semibold'>
								{profile.followingCount}
							</div>
							<div className='text-muted-foreground'>Following</div>
						</div>
					</div>
				</CardContent>
			</Card>

			<div className='grid gap-6 lg:grid-cols-[2fr_1fr]'>
				<Card>
					<CardHeader>
						<CardTitle>Public info</CardTitle>
						<CardDescription>
							Demographic details shared by this user.
						</CardDescription>
					</CardHeader>
					<CardContent>
						<div className='grid gap-3 text-sm'>
							{profile.bio ? (
								<p className='text-foreground/90'>{profile.bio}</p>
							) : (
								<p className='text-muted-foreground'>No bio yet.</p>
							)}
							<div className='grid gap-2 sm:grid-cols-2'>
								<div>
									<div className='text-xs text-muted-foreground'>
										Occupation
									</div>
									<div>{profile.occupation ?? "Not shared"}</div>
								</div>
								<div>
									<div className='text-xs text-muted-foreground'>Location</div>
									<div>{profile.location ?? "Not shared"}</div>
								</div>
								<div>
									<div className='text-xs text-muted-foreground'>Email</div>
									<div>{profile.email ?? "Hidden"}</div>
								</div>
								<div>
									<div className='text-xs text-muted-foreground'>Contact</div>
									<div>{profile.contact ?? "Hidden"}</div>
								</div>
								<div>
									<div className='text-xs text-muted-foreground'>Website</div>
									{profile.website ? (
										<a
											href={profile.website}
											target='_blank'
											rel='noreferrer'
											className='text-primary underline underline-offset-4'
										>
											{profile.website}
										</a>
									) : (
										<div>Not shared</div>
									)}
								</div>
							</div>
						</div>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Skills</CardTitle>
						<CardDescription>
							Encrypted skills shared by the user.
						</CardDescription>
					</CardHeader>
					<CardContent>
						{profile.skills?.length ? (
							<div className='flex flex-wrap gap-2'>
								{profile.skills.map((skill) => (
									<span
										key={skill}
										className='rounded-full border border-border bg-muted/60 px-3 py-1 text-xs'
									>
										#{skill}
									</span>
								))}
							</div>
						) : (
							<p className='text-sm text-muted-foreground'>
								No skills shared yet.
							</p>
						)}
					</CardContent>
				</Card>
			</div>

			<Card>
				<CardHeader>
					<CardTitle>Shared posts</CardTitle>
					<CardDescription>
						Recent requests, offers, and updates.
					</CardDescription>
				</CardHeader>
				<CardContent>
					{error ? <p className='text-sm text-red-600'>{error}</p> : null}
					{posts.length ? (
						<div className='space-y-4'>
							{posts.map((post) => (
								<Card key={post.id} size='sm'>
									<CardHeader>
										<CardTitle>{post.title}</CardTitle>
										<CardDescription>
											{formatDate(post.createdAt)} - {post.category}
										</CardDescription>
									</CardHeader>
									<CardContent>
										<p className='text-sm text-foreground/90'>{post.content}</p>
										{post.tags?.length ? (
											<div className='mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground'>
												{post.tags.map((tag) => (
													<span
														key={`${post.id}-${tag}`}
														className='rounded bg-muted px-2 py-0.5'
													>
														#{tag}
													</span>
												))}
											</div>
										) : null}
									</CardContent>
								</Card>
							))}
							<div className='flex flex-wrap items-center gap-2'>
								<Button
									type='button'
									variant='outline'
									onClick={() => loadPage(page - 1)}
									disabled={isPaging || page <= 1}
								>
									Previous
								</Button>
								<Button
									type='button'
									variant='outline'
									onClick={() => loadPage(page + 1)}
									disabled={isPaging || !hasMore}
								>
									Next
								</Button>
								<span className='text-xs text-muted-foreground'>
									Page {page}
								</span>
							</div>
						</div>
					) : (
						<p className='text-sm text-muted-foreground'>
							No shared posts yet.
						</p>
					)}
				</CardContent>
			</Card>
		</div>
	);
}
