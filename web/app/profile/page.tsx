"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiGet } from "@/lib/api";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";

type DashboardUser = {
	username: string | null;
};

type DashboardPayload = {
	user?: DashboardUser;
};

export default function ProfileRedirectPage() {
	const router = useRouter();
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let isMounted = true;
		apiGet("/dashboard")
			.then((data) => {
				if (!isMounted) return;
				const payload = data as DashboardPayload;
				const username = payload.user?.username?.trim();
				if (username) {
					router.replace(`/profile/${encodeURIComponent(username)}`);
					return;
				}
				router.replace("/auth/login");
			})
			.catch(() => {
				if (!isMounted) return;
				setError("Please sign in to view your profile.");
				router.replace("/auth/login");
			});

		return () => {
			isMounted = false;
		};
	}, [router]);

	return (
		<div className='p-6'>
			<Card>
				<CardHeader>
					<CardTitle>Opening your profile</CardTitle>
					<CardDescription>Checking your session...</CardDescription>
				</CardHeader>
				<CardContent>
					{error ? (
						<p className='text-sm text-muted-foreground'>{error}</p>
					) : (
						<div className='h-4 w-40 rounded bg-muted/40 animate-pulse' />
					)}
				</CardContent>
			</Card>
		</div>
	);
}
