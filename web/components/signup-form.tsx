"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
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

export function SignupForm({ ...props }: React.ComponentProps<typeof Card>) {
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
            const username = String(formData.get("username") || "").trim();
            const email = String(formData.get("email") || "").trim();
            const password = String(formData.get("password") || "");
            const confirmPassword = String(formData.get("confirmPassword") || "");

            if (password !== confirmPassword) {
                setError("Passwords do not match");
                return;
            }

            await apiPost("/auth/register", { username, email, password });
            router.push("/feed");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Signup failed");
        } finally {
            setIsLoading(false);
        }
    }

    if (isChecking) {
        return (
            <Card {...props}>
                <CardHeader>
                    <div className='h-5 w-48 rounded bg-muted/60 animate-pulse' />
                    <div className='h-4 w-64 rounded bg-muted/40 animate-pulse' />
                </CardHeader>
                <CardContent>
                    <div className='space-y-4'>
                        <div className='h-4 w-24 rounded bg-muted/40 animate-pulse' />
                        <div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
                        <div className='h-4 w-24 rounded bg-muted/40 animate-pulse' />
                        <div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
                        <div className='h-4 w-24 rounded bg-muted/40 animate-pulse' />
                        <div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
                        <div className='h-4 w-32 rounded bg-muted/40 animate-pulse' />
                        <div className='h-10 w-full rounded bg-muted/30 animate-pulse' />
                        <div className='flex items-center gap-3 pt-2'>
                            <div className='h-9 w-28 rounded bg-muted/40 animate-pulse' />
                            <div className='h-9 w-36 rounded bg-muted/30 animate-pulse' />
                        </div>
                        <div className='h-4 w-52 rounded bg-muted/40 animate-pulse' />
                    </div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card {...props}>
            <CardHeader>
                <CardTitle>Create an account</CardTitle>
                <CardDescription>
                    Enter your information below to create your account
                </CardDescription>
            </CardHeader>
            <CardContent>
                <form onSubmit={handleSubmit}>
                    <FieldGroup>
                        <Field>
                            <FieldLabel htmlFor='username'>Username</FieldLabel>
                            <Input
                                id='username'
                                name='username'
                                type='text'
                                placeholder='Your Name'
                                required
                            />
                        </Field>
                        <Field>
                            <FieldLabel htmlFor='email'>Email</FieldLabel>
                            <Input
                                id='email'
                                name='email'
                                type='email'
                                placeholder='m@example.com'
                                required
                            />
                            <FieldDescription>
                                We&apos;ll use this to contact you. We will not share your email
                                with anyone else.
                            </FieldDescription>
                        </Field>
                        <Field>
                            <FieldLabel htmlFor='password'>Password</FieldLabel>
                            <Input id='password' name='password' type='password' required />
                            <FieldDescription>
                                Use 8 or more chars, uppercase, lowercase, number, and symbol.
                            </FieldDescription>
                        </Field>
                        <Field>
                            <FieldLabel htmlFor='confirm-password'>
                                Confirm Password
                            </FieldLabel>
                            <Input
                                id='confirm-password'
                                name='confirmPassword'
                                type='password'
                                required
                            />
                            <FieldDescription>Please confirm your password.</FieldDescription>
                        </Field>
                        <FieldGroup>
                            <Field>
                                <Button type='submit' disabled={isLoading}>
                                    {isLoading ? "Creating..." : "Create Account"}
                                </Button>
                                <Button variant='outline' type='button' disabled={isLoading}>
                                    Sign up with Google
                                </Button>
                                {error ? (
                                    <FieldDescription className='px-6 text-center text-destructive'>
                                        {error}
                                    </FieldDescription>
                                ) : null}
                                <FieldDescription className='px-6 text-center'>
                                    Already have an account?{" "}
                                    <a href='#' className='text-primary hover:underline'>
                                        Sign in
                                    </a>
                                </FieldDescription>
                            </Field>
                        </FieldGroup>
                    </FieldGroup>
                </form>
            </CardContent>
        </Card>
    );
}
