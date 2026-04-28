"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { apiGet, apiPatch, apiPost, apiRequest } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardHeader,
	CardTitle,
	CardDescription,
	CardContent,
	CardFooter,
} from "@/components/ui/card";

type FeedPost = {
	id: string;
	title: string;
	content: string;
	category: string;
	tags: string[];
	createdAt: string;
	author: string | null;
};

type CommentItem = {
	id: string;
	postId: string;
	author: string;
	content: string;
	createdAt: string;
	parentComment: string | null;
};

const FeedPage = () => {
	const [posts, setPosts] = useState<FeedPost[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [isLoadingMore, setIsLoadingMore] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [page, setPage] = useState(1);
	const [hasMore, setHasMore] = useState(true);
	const [currentUserId, setCurrentUserId] = useState<string | null>(null);
	const [currentUserRole, setCurrentUserRole] = useState<string | null>(null);
	const [adminMode, setAdminMode] = useState(false);
	const [editingPostId, setEditingPostId] = useState<string | null>(null);
	const [editTitle, setEditTitle] = useState("");
	const [editContent, setEditContent] = useState("");
	const [isSavingEdit, setIsSavingEdit] = useState(false);
	const [commentsByPost, setCommentsByPost] = useState<
		Record<string, CommentItem[]>
	>({});
	const [commentsOpen, setCommentsOpen] = useState<Record<string, boolean>>({});
	const [commentsLoaded, setCommentsLoaded] = useState<Record<string, boolean>>(
		{},
	);
	const [commentLoading, setCommentLoading] = useState<Record<string, boolean>>(
		{},
	);
	const [commentInputs, setCommentInputs] = useState<Record<string, string>>(
		{},
	);
	const loadMoreRef = useRef<HTMLDivElement | null>(null);
	const editFormRef = useRef<HTMLFormElement | null>(null);

	useEffect(() => {
		let isMounted = true;
		apiGet(`/posts?page=1&limit=10`)
			.then((data) => {
				if (!isMounted) return;
				const payload = data as {
					posts: FeedPost[];
					hasMore: boolean;
					currentUserId: string | null;
					currentUserRole: string | null;
				};
				setPosts(payload.posts ?? []);
				setHasMore(Boolean(payload.hasMore));
				setCurrentUserId(payload.currentUserId ?? null);
				setCurrentUserRole(payload.currentUserRole ?? null);
				setPage(1);
			})
			.catch((err) => {
				if (!isMounted) return;
				setError(err instanceof Error ? err.message : "Failed to load feed");
			})
			.finally(() => {
				if (isMounted) setIsLoading(false);
			});

		return () => {
			isMounted = false;
		};
	}, []);

	useEffect(() => {
		if (typeof window === "undefined") return;
		const stored = window.sessionStorage.getItem("adminMode") === "true";
		setAdminMode(stored);
	}, []);

	useEffect(() => {
		if (typeof window === "undefined") return;
		window.sessionStorage.setItem("adminMode", adminMode ? "true" : "false");
	}, [adminMode]);

	useEffect(() => {
		if (!hasMore || isLoading || isLoadingMore) return;
		const node = loadMoreRef.current;
		if (!node) return;

		const observer = new IntersectionObserver(
			(entries) => {
				const entry = entries[0];
				if (entry?.isIntersecting) {
					setIsLoadingMore(true);
					const nextPage = page + 1;
					apiGet(`/posts?page=${nextPage}&limit=10`)
						.then((data) => {
							const payload = data as {
								posts: FeedPost[];
								hasMore: boolean;
								currentUserId: string | null;
								currentUserRole: string | null;
							};
							setPosts((prev) => [...prev, ...(payload.posts ?? [])]);
							setHasMore(Boolean(payload.hasMore));
							setCurrentUserId((prev) => prev ?? payload.currentUserId ?? null);
							setCurrentUserRole(
								(prev) => prev ?? payload.currentUserRole ?? null,
							);
							setPage(nextPage);
						})
						.catch((err) => {
							setError(
								err instanceof Error
									? err.message
									: "Failed to load more posts",
							);
						})
						.finally(() => setIsLoadingMore(false));
				}
			},
			{ rootMargin: "200px" },
		);

		observer.observe(node);
		return () => observer.disconnect();
	}, [hasMore, isLoading, isLoadingMore, page]);

	function startEdit(post: FeedPost) {
		setEditingPostId(post.id);
		setEditTitle(post.title);
		setEditContent(post.content);
		setTimeout(() => {
			editFormRef.current?.scrollIntoView({
				behavior: "smooth",
				block: "center",
			});
		}, 0);
	}

	async function submitEdit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (!editingPostId) return;
		setIsSavingEdit(true);
		setError(null);

		try {
			await apiPatch(`/posts/${editingPostId}`, {
				title: editTitle.trim(),
				content: editContent.trim(),
			});
			setPosts((prev) =>
				prev.map((post) =>
					post.id === editingPostId
						? { ...post, title: editTitle, content: editContent }
						: post,
				),
			);
			setEditingPostId(null);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to update post");
		} finally {
			setIsSavingEdit(false);
		}
	}

	async function deletePost(postId: string) {
		setError(null);
		try {
			await apiRequest(`/posts/${postId}`, { method: "DELETE" });
			setPosts((prev) => prev.filter((post) => post.id !== postId));
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to delete post");
		}
	}

	async function loadComments(postId: string, force = false) {
		if (!force && commentsLoaded[postId]) return;
		setCommentLoading((prev) => ({ ...prev, [postId]: true }));
		try {
			const data = await apiGet(`/comments?postId=${postId}&limit=20`);
			const payload = data as { comments: CommentItem[] };
			setCommentsByPost((prev) => ({
				...prev,
				[postId]: payload.comments ?? [],
			}));
			setCommentsLoaded((prev) => ({ ...prev, [postId]: true }));
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to load comments");
		} finally {
			setCommentLoading((prev) => ({ ...prev, [postId]: false }));
		}
	}

	async function toggleComments(postId: string) {
		const isOpen = commentsOpen[postId];
		if (isOpen) {
			setCommentsOpen((prev) => ({ ...prev, [postId]: false }));
			return;
		}
		setCommentsOpen((prev) => ({ ...prev, [postId]: true }));
		await loadComments(postId);
	}

	async function submitComment(postId: string) {
		const content = (commentInputs[postId] || "").trim();
		if (!content) {
			setError("Comment is required");
			return;
		}
		try {
			await apiPost("/comments", { postId, content });
			setCommentInputs((prev) => ({ ...prev, [postId]: "" }));
			await loadComments(postId, true);
			setCommentsOpen((prev) => ({ ...prev, [postId]: true }));
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to add comment");
		}
	}

	return (
		<div className='space-y-4'>
			<div className='flex items-center justify-between'>
				<div>
					<h2 className='text-lg font-semibold'>Feed</h2>
					<p className='text-sm text-muted-foreground'>
						Latest encrypted posts.
					</p>
				</div>
				<Button asChild>
					<Link href='/posts/new'>Create post</Link>
				</Button>
			</div>

			{isLoading ? (
				<Card>
					<CardHeader>
						<CardTitle>Loading posts</CardTitle>
						<CardDescription>Decrypting your feed...</CardDescription>
					</CardHeader>
					<CardContent>
						<div className='h-4 w-40 rounded bg-muted/40 animate-pulse' />
					</CardContent>
				</Card>
			) : null}

			{error ? (
				<Card>
					<CardHeader>
						<CardTitle>Feed unavailable</CardTitle>
						<CardDescription>{error}</CardDescription>
					</CardHeader>
				</Card>
			) : null}

			{!isLoading && !error && posts.length === 0 ? (
				<Card>
					<CardHeader>
						<CardTitle>No posts yet</CardTitle>
						<CardDescription>Create the first post.</CardDescription>
					</CardHeader>
				</Card>
			) : null}

			{currentUserRole === "admin" ? (
				<div className='flex items-center gap-2 text-sm text-muted-foreground'>
					<input
						id='admin-mode'
						type='checkbox'
						checked={adminMode}
						onChange={(event) => setAdminMode(event.target.checked)}
						className='size-4 rounded border border-input'
					/>
					<label htmlFor='admin-mode'>Admin mode</label>
				</div>
			) : null}

			{posts.map((post) => (
				<Card key={post.id} className='w-full'>
					<CardHeader>
						<CardTitle>{post.title}</CardTitle>
						<CardDescription>
							{new Date(post.createdAt).toLocaleString()} • {post.category}
						</CardDescription>
					</CardHeader>
					<CardContent>
						<p className='text-sm text-foreground/90'>{post.content}</p>
						{post.author &&
						(post.author === currentUserId ||
							(currentUserRole === "admin" && adminMode)) ? (
							<div className='mt-3 flex gap-2'>
								<Button
									variant='outline'
									type='button'
									onClick={() => startEdit(post)}
								>
									Edit
								</Button>
								<Button
									variant='destructive'
									type='button'
									onClick={() => deletePost(post.id)}
								>
									Delete
								</Button>
							</div>
						) : null}
					</CardContent>
					<CardFooter>
						<div className='w-full space-y-3'>
							<div className='flex flex-wrap gap-2 text-xs text-muted-foreground'>
								{post.tags.map((tag) => (
									<span key={tag} className='rounded bg-muted px-2 py-0.5'>
										#{tag}
									</span>
								))}
							</div>

							<div className='space-y-2'>
								<Button
									variant='outline'
									type='button'
									onClick={() => toggleComments(post.id)}
									disabled={commentLoading[post.id]}
								>
									{commentLoading[post.id]
										? "Loading..."
										: commentsOpen[post.id]
											? "Hide comments"
											: commentsLoaded[post.id]
												? "Show comments"
												: "Load comments"}
									<span className='ml-2 rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground'>
										{commentsLoaded[post.id]
											? (commentsByPost[post.id] || []).length
											: "-"}
									</span>
								</Button>

								{commentsOpen[post.id]
									? (commentsByPost[post.id] || []).map((comment) => (
											<div
												key={comment.id}
												className='text-sm text-muted-foreground'
											>
												{comment.content}
											</div>
										))
									: null}

								<div className='flex gap-2'>
									<input
										className='h-9 flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm'
										placeholder='Write a comment...'
										value={commentInputs[post.id] || ""}
										onChange={(event) =>
											setCommentInputs((prev) => ({
												...prev,
												[post.id]: event.target.value,
											}))
										}
									/>
									<Button type='button' onClick={() => submitComment(post.id)}>
										Comment
									</Button>
								</div>
							</div>
						</div>
					</CardFooter>
				</Card>
			))}

			{editingPostId ? (
				<Card>
					<CardHeader>
						<CardTitle>Edit post</CardTitle>
						<CardDescription>Updates are re-encrypted on save.</CardDescription>
					</CardHeader>
					<CardContent>
						<form ref={editFormRef} onSubmit={submitEdit} className='space-y-3'>
							<label className='block text-sm font-medium'>Title</label>
							<input
								className='h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm'
								value={editTitle}
								onChange={(event) => setEditTitle(event.target.value)}
								required
							/>
							<label className='block text-sm font-medium'>Content</label>
							<textarea
								className='min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm'
								value={editContent}
								onChange={(event) => setEditContent(event.target.value)}
								required
							/>
							<div className='flex gap-2'>
								<Button type='submit' disabled={isSavingEdit}>
									{isSavingEdit ? "Saving..." : "Save"}
								</Button>
								<Button
									type='button'
									variant='outline'
									onClick={() => setEditingPostId(null)}
								>
									Cancel
								</Button>
							</div>
						</form>
					</CardContent>
				</Card>
			) : null}

			<div ref={loadMoreRef} />
			{isLoadingMore ? (
				<Card>
					<CardContent>
						<div className='h-4 w-40 rounded bg-muted/40 animate-pulse' />
					</CardContent>
				</Card>
			) : null}
		</div>
	);
};

export default FeedPage;
