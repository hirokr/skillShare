"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiPost } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

const categories = ["need", "offer", "question", "event", "other"];

export default function NewPostPage() {
	const router = useRouter();
	const [error, setError] = useState<string | null>(null);
	const [isSaving, setIsSaving] = useState(false);

	async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setError(null);
		setIsSaving(true);

		try {
			const formData = new FormData(event.currentTarget);
			const title = String(formData.get("title") || "").trim();
			const content = String(formData.get("content") || "").trim();
			const category = String(formData.get("category") || "need");
			const tags = String(formData.get("tags") || "").trim();

			if (!title || !content) {
				setError("Title and content are required");
				return;
			}

			await apiPost("/posts", { title, content, category, tags });
			router.push("/feed");
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to create post");
		} finally {
			setIsSaving(false);
		}
	}

	return (
		<div className='mx-auto w-full max-w-6xl px-8 pb-24 pt-14 sm:px-10 lg:px-16'>
			<Card>
				<CardHeader>
					<CardTitle>Create a post</CardTitle>
					<CardDescription>
						Posts are encrypted before they are stored.
					</CardDescription>
				</CardHeader>
				<CardContent>
					<form onSubmit={handleSubmit} className='space-y-4'>
						<FieldGroup>
							<Field>
								<FieldLabel htmlFor='title'>Title</FieldLabel>
								<Input id='title' name='title' maxLength={120} required />
							</Field>
							<Field>
								<FieldLabel htmlFor='content'>Content</FieldLabel>
								<Textarea id='content' name='content' rows={6} required />
							</Field>
							<Field>
								<FieldLabel htmlFor='category'>Category</FieldLabel>
								<select
									id='category'
									name='category'
									className='h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm'
									defaultValue='need'
								>
									{categories.map((cat) => (
										<option key={cat} value={cat}>
											{cat}
										</option>
									))}
								</select>
							</Field>
							<Field>
								<FieldLabel htmlFor='tags'>Tags</FieldLabel>
								<Input id='tags' name='tags' placeholder='food, urgent' />
							</Field>
						</FieldGroup>
						{error ? <div className='text-sm text-red-600'>{error}</div> : null}
						<Button type='submit' disabled={isSaving}>
							{isSaving ? "Publishing..." : "Publish"}
						</Button>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
