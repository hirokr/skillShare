"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { apiGet, apiPost } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import {
	Field,
	FieldDescription,
	FieldGroup,
	FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";

export function LoginForm({
	className,
	...props
}: React.ComponentProps<"div">) {
	const router = useRouter();
	const [error, setError] = useState<string | null>(null);
	const [isLoading, setIsLoading] = useState(false);
	const [isChecking, setIsChecking] = useState(true);

	useEffect(() => {
		let isMounted = true;
		apiGet("/auth/session")
			.then(() => {
				if (isMounted) {
					router.replace("/feed");
				}
			})
			.catch(() => null)
			.finally(() => {
				if (isMounted) {
					setIsChecking(false);
				}
			});
		return () => {
			isMounted = false;
		};
	}, [router]);

	async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
		event.preventDefault();
		setError(null);
		setIsLoading(true);

		try {
			const formData = new FormData(event.currentTarget);
			const email = String(formData.get("email") || "").trim();
			const password = String(formData.get("password") || "");

			await apiPost("/auth/login", { email, password });
			router.push("/feed");
		} catch (err) {
			setError(err instanceof Error ? err.message : "Login failed");
		} finally {
			setIsLoading(false);
		}
	}

	if (isChecking) {
		return (
			<div className={cn("flex flex-col gap-6", className)} {...props}>
				<Card>
					<CardHeader>
						<div className='h-5 w-40 rounded bg-muted/60 animate-pulse' />
						<div className='h-4 w-56 rounded bg-muted/40 animate-pulse' />
					</CardHeader>
					<CardContent>
						<div className='space-y-4'>
							<div className='h-4 w-24 rounded bg-muted/40 animate-pulse' />
							<div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
							<div className='h-4 w-24 rounded bg-muted/40 animate-pulse' />
							<div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
							<div className='flex items-center gap-3 pt-2'>
								<div className='h-9 w-24 rounded bg-muted/40 animate-pulse' />
								<div className='h-9 w-36 rounded bg-muted/30 animate-pulse' />
							</div>
							<div className='h-4 w-48 rounded bg-muted/40 animate-pulse' />
						</div>
					</CardContent>
				</Card>
			</div>
		);
	}

	return (
		<div className={cn("flex flex-col gap-6", className)} {...props}>
			<Card>
				<CardHeader>
					<CardTitle>Login to your account</CardTitle>
					<CardDescription>
						Enter your email below to login to your account
					</CardDescription>
				</CardHeader>
				<CardContent>
					<form onSubmit={handleSubmit}>
						<FieldGroup>
							<Field>
								<FieldLabel htmlFor='email'>Email</FieldLabel>
								<Input
									id='email'
									name='email'
									type='email'
									placeholder='m@example.com'
									required
								/>
							</Field>
							<Field>
								<div className='flex items-center'>
									<FieldLabel htmlFor='password'>Password</FieldLabel>
									<a
										href='#'
										className='ml-auto inline-block text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline'
									>
										Forgot your password?
									</a>
								</div>
								<Input id='password' name='password' type='password' required />
							</Field>
							<Field>
								<Button type='submit' disabled={isLoading}>
									{isLoading ? "Logging in..." : "Login"}
								</Button>
								<Button variant='outline' type='button' disabled={isLoading}>
									Login with Google
								</Button>
								{error ? (
									<FieldDescription className='text-center text-destructive'>
										{error}
									</FieldDescription>
								) : null}
								<FieldDescription className='text-center'>
									Don&apos;t have an account?{" "}
									<a href='#' className='text-primary hover:underline'>
										Sign up
									</a>
								</FieldDescription>
							</Field>
						</FieldGroup>
					</form>
				</CardContent>
			</Card>
		</div>
	);
}
