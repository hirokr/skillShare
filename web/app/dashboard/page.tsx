"use client";

import { useEffect, useState } from "react";
import { apiGet, apiPatch } from "@/lib/api";
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

type DashboardUser = {
	id: string;
	username: string | null;
	email: string | null;
	contact: string | null;
	role: string;
	profilePictureUrl: string | null;
};

type DashboardProfile = {
	displayName: string;
	avatarUrl: string | null;
	bannerUrl: string | null;
	bio: string | null;
	location: string | null;
	website: string | null;
	occupation: string | null;
	privacy: {
		showEmail: boolean;
		showContact: boolean;
		showLocation: boolean;
		allowMessages: boolean;
	};
	postCount: number;
	followerCount: number;
	followingCount: number;
};

const URL_REGEX = /^https?:\/\//i;

function validateProfileInput(values: {
	displayName: string;
	avatarUrl: string;
	bannerUrl: string;
	bio: string;
	location: string;
	website: string;
	occupation: string;
}) {
	const errors: Record<string, string> = {};
	if (values.displayName.length > 60) {
		errors.displayName = "Display name is too long";
	}
	if (values.avatarUrl && values.avatarUrl.length > 500) {
		errors.avatarUrl = "Avatar URL is too long";
	}
	if (values.bannerUrl && values.bannerUrl.length > 500) {
		errors.bannerUrl = "Banner URL is too long";
	}
	if (values.bio.length > 500) {
		errors.bio = "Bio is too long";
	}
	if (values.location.length > 120) {
		errors.location = "Location is too long";
	}
	if (values.website && values.website.length > 200) {
		errors.website = "Website is too long";
	}
	if (values.occupation.length > 120) {
		errors.occupation = "Occupation is too long";
	}
	if (values.website && !URL_REGEX.test(values.website)) {
		errors.website = "Website must start with http:// or https://";
	}
	if (values.avatarUrl && !URL_REGEX.test(values.avatarUrl)) {
		errors.avatarUrl = "Avatar URL must start with http:// or https://";
	}
	if (values.bannerUrl && !URL_REGEX.test(values.bannerUrl)) {
		errors.bannerUrl = "Banner URL must start with http:// or https://";
	}
	return errors;
}

export default function DashboardPage() {
	const [user, setUser] = useState<DashboardUser | null>(null);
	const [profile, setProfile] = useState<DashboardProfile | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [isSaving, setIsSaving] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

	useEffect(() => {
		let isMounted = true;
		apiGet("/dashboard")
			.then((data) => {
				if (!isMounted) return;
				const payload = data as {
					user: DashboardUser;
					profile: DashboardProfile;
				};
				setUser(payload.user);
				setProfile(payload.profile);
			})
			.catch((err) => {
				if (!isMounted) return;
				setError(
					err instanceof Error ? err.message : "Failed to load dashboard",
				);
			})
			.finally(() => {
				if (isMounted) setIsLoading(false);
			});

		return () => {
			isMounted = false;
		};
	}, []);

	async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setError(null);
		setFieldErrors({});
		setIsSaving(true);

		try {
			const formData = new FormData(event.currentTarget);
			const payload = {
				displayName: String(formData.get("displayName") || "").trim(),
				avatarUrl: String(formData.get("avatarUrl") || "").trim(),
				bannerUrl: String(formData.get("bannerUrl") || "").trim(),
				bio: String(formData.get("bio") || "").trim(),
				location: String(formData.get("location") || "").trim(),
				website: String(formData.get("website") || "").trim(),
				occupation: String(formData.get("occupation") || "").trim(),
			};

			const validationErrors = validateProfileInput(payload);
			if (Object.keys(validationErrors).length > 0) {
				setFieldErrors(validationErrors);
				return;
			}

			const data = await apiPatch("/dashboard/profile", payload);
			const result = data as { profile: DashboardProfile };
			setProfile(result.profile);
			setFieldErrors({});
		} catch (err) {
			setError(err instanceof Error ? err.message : "Update failed");
		} finally {
			setIsSaving(false);
		}
	}

	if (isLoading) {
		return (
			<div className='p-6'>
				<Card>
					<CardHeader>
						<CardTitle>Loading dashboard</CardTitle>
						<CardDescription>Getting your encrypted profile...</CardDescription>
					</CardHeader>
					<CardContent>
						<div className='h-4 w-32 rounded bg-muted/40 animate-pulse' />
					</CardContent>
				</Card>
			</div>
		);
	}

	if (!user || !profile) {
		return (
			<div className='p-6'>
				<Card>
					<CardHeader>
						<CardTitle>Dashboard unavailable</CardTitle>
						<CardDescription>{error ?? "Try again."}</CardDescription>
					</CardHeader>
				</Card>
			</div>
		);
	}

	return (
		<div className='p-6 space-y-6'>
			<Card>
				<CardHeader>
					<CardTitle>
						Welcome back{user.username ? `, ${user.username}` : ""}
					</CardTitle>
					<CardDescription>Manage your encrypted profile data.</CardDescription>
				</CardHeader>
				<CardContent>
					<div className='grid gap-2 text-sm'>
						<div>Role: {user.role}</div>
						<div>Email: {user.email ?? "Not set"}</div>
						<div>Contact: {user.contact ?? "Not set"}</div>
						<div>Posts: {profile.postCount}</div>
						<div>Followers: {profile.followerCount}</div>
						<div>Following: {profile.followingCount}</div>
					</div>
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Profile settings</CardTitle>
					<CardDescription>All sensitive fields are encrypted.</CardDescription>
				</CardHeader>
				<CardContent>
					<form onSubmit={handleSubmit} className='space-y-4'>
						<FieldGroup>
							<Field>
								<FieldLabel htmlFor='displayName'>Display name</FieldLabel>
								<Input
									id='displayName'
									name='displayName'
									maxLength={60}
									className={
										fieldErrors.displayName
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.displayName}
								/>
								{fieldErrors.displayName ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.displayName}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='avatarUrl'>Avatar URL</FieldLabel>
								<Input
									id='avatarUrl'
									name='avatarUrl'
									maxLength={500}
									className={
										fieldErrors.avatarUrl
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.avatarUrl ?? ""}
								/>
								{fieldErrors.avatarUrl ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.avatarUrl}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='bannerUrl'>Banner URL</FieldLabel>
								<Input
									id='bannerUrl'
									name='bannerUrl'
									maxLength={500}
									className={
										fieldErrors.bannerUrl
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.bannerUrl ?? ""}
								/>
								{fieldErrors.bannerUrl ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.bannerUrl}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='occupation'>Occupation</FieldLabel>
								<Input
									id='occupation'
									name='occupation'
									maxLength={120}
									className={
										fieldErrors.occupation
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.occupation ?? ""}
								/>
								{fieldErrors.occupation ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.occupation}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='location'>Location</FieldLabel>
								<Input
									id='location'
									name='location'
									maxLength={120}
									className={
										fieldErrors.location
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.location ?? ""}
								/>
								{fieldErrors.location ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.location}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='website'>Website</FieldLabel>
								<Input
									id='website'
									name='website'
									maxLength={200}
									className={
										fieldErrors.website
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
									defaultValue={profile.website ?? ""}
								/>
								{fieldErrors.website ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.website}
									</FieldDescription>
								) : null}
							</Field>
							<Field>
								<FieldLabel htmlFor='bio'>Bio</FieldLabel>
								<Textarea
									id='bio'
									name='bio'
									defaultValue={profile.bio ?? ""}
									maxLength={500}
									rows={4}
									className={
										fieldErrors.bio
											? "ring-1 ring-red-500 focus-visible:ring-red-500"
											: undefined
									}
								/>
								{fieldErrors.bio ? (
									<FieldDescription className='text-red-600'>
										{fieldErrors.bio}
									</FieldDescription>
								) : null}
							</Field>
						</FieldGroup>
						{error ? <div className='text-sm text-red-600'>{error}</div> : null}
						<Button type='submit' disabled={isSaving}>
							{isSaving ? "Saving..." : "Save changes"}
						</Button>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
