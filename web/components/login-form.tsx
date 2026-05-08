"use client";

import { useEffect, useRef, useState } from "react";
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

// ─── Types ────────────────────────────────────────────────────────────────────

type LoginStep = "credentials" | "totp";

// ─── Loading skeleton ─────────────────────────────────────────────────────────

function LoginSkeleton({ className }: { className?: string }) {
    return (
        <div className={cn("flex flex-col gap-6", className)}>
            <Card>
                <CardHeader>
                    <div className="h-5 w-40 rounded bg-muted/60 animate-pulse" />
                    <div className="h-4 w-56 rounded bg-muted/40 animate-pulse" />
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="h-4 w-24 rounded bg-muted/40 animate-pulse" />
                        <div className="h-10 w-full rounded bg-muted/30 animate-pulse" />
                        <div className="h-4 w-24 rounded bg-muted/40 animate-pulse" />
                        <div className="h-10 w-full rounded bg-muted/30 animate-pulse" />
                        <div className="flex items-center gap-3 pt-2">
                            <div className="h-9 w-24 rounded bg-muted/40 animate-pulse" />
                        </div>
                        <div className="h-4 w-48 rounded bg-muted/40 animate-pulse" />
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}

// ─── Step 1: Credentials form ─────────────────────────────────────────────────

interface CredentialsFormProps {
    onRequires2FA: (tempToken: string) => void;
    onSuccess: () => void;
}

function CredentialsForm({ onRequires2FA, onSuccess }: CredentialsFormProps) {
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(false);

    async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
        event.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            const formData = new FormData(event.currentTarget);
            const email = String(formData.get("email") || "").trim();
            const password = String(formData.get("password") || "");

            const data = await apiPost("/auth/login", { email, password }) as {
                requires2FA?: boolean;
                tempToken?: string;
            };

            if (data?.requires2FA && data.tempToken) {
                onRequires2FA(data.tempToken);
            } else {
                onSuccess();
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : "Login failed");
        } finally {
            setIsLoading(false);
        }
    }

    return (
        <form onSubmit={handleSubmit}>
            <FieldGroup>
                <Field>
                    <FieldLabel htmlFor="email">Email</FieldLabel>
                    <Input
                        id="email"
                        name="email"
                        type="email"
                        placeholder="example@gmail.com"
                        required
                        autoComplete="email"
                    />
                </Field>
                <Field>
                    <div className="flex items-center">
                        <FieldLabel htmlFor="password">Password</FieldLabel>
                        {/* <a
                            href="#"
                            className="ml-auto inline-block text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
                        >
                            Forgot your password?
                        </a> */}
                    </div>
                    <Input
                        id="password"
                        name="password"
                        type="password"
                        required
                        autoComplete="current-password"
                    />
                </Field>
                <Field>
                    <Button type="submit" disabled={isLoading}>
                        {isLoading ? "Checking..." : "Continue"}
                    </Button>
                    {error ? (
                        <FieldDescription className="text-center text-destructive">
                            {error}
                        </FieldDescription>
                    ) : null}
                    <FieldDescription className="text-center">
                        Don&apos;t have an account?{" "}
                        <a href="/auth/signup" className="text-primary hover:underline">
                            Sign up
                        </a>
                    </FieldDescription>
                </Field>
            </FieldGroup>
        </form>
    );
}

// ─── Step 2: TOTP form ────────────────────────────────────────────────────────

interface TotpFormProps {
    tempToken: string;
    onSuccess: () => void;
    onBack: () => void;
}

function TotpForm({ tempToken, onSuccess, onBack }: TotpFormProps) {
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    // Auto-focus the code input when this step mounts
    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
        event.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            const formData = new FormData(event.currentTarget);
            const totpCode = String(formData.get("totpCode") || "").replace(/\s/g, "");

            if (!/^\d{6}$/.test(totpCode)) {
                setError("Enter the 6-digit code from your authenticator app");
                return;
            }

            await apiPost("/auth/2fa/verify", { tempToken, totpCode });
            onSuccess();
        } catch (err) {
            setError(err instanceof Error ? err.message : "Verification failed");
        } finally {
            setIsLoading(false);
        }
    }

    return (
        <form onSubmit={handleSubmit}>
            <FieldGroup>
                <Field>
                    <FieldLabel htmlFor="totpCode">Authentication code</FieldLabel>
                    <Input
                        ref={inputRef}
                        id="totpCode"
                        name="totpCode"
                        type="text"
                        inputMode="numeric"
                        pattern="\d{6}"
                        maxLength={6}
                        placeholder="000000"
                        required
                        autoComplete="one-time-code"
                        className="tracking-widest text-center text-lg"
                    />
                    <FieldDescription>
                        Open your authenticator app and enter the 6-digit code.
                    </FieldDescription>
                </Field>
                <Field>
                    <Button type="submit" disabled={isLoading}>
                        {isLoading ? "Verifying..." : "Verify"}
                    </Button>
                    <Button
                        type="button"
                        variant="outline"
                        disabled={isLoading}
                        onClick={onBack}
                    >
                        Back
                    </Button>
                    {error ? (
                        <FieldDescription className="text-center text-destructive">
                            {error}
                        </FieldDescription>
                    ) : null}
                </Field>
            </FieldGroup>
        </form>
    );
}

// ─── Main LoginForm component ─────────────────────────────────────────────────

export function LoginForm({
    className,
    ...props
}: React.ComponentProps<"div">) {
    const router = useRouter();
    const [step, setStep] = useState<LoginStep>("credentials");
    const [tempToken, setTempToken] = useState<string | null>(null);
    const [isChecking, setIsChecking] = useState(true);

    // Redirect already-authenticated users
    useEffect(() => {
        let isMounted = true;
        apiGet("/auth/session")
            .then(() => { if (isMounted) router.replace("/feed"); })
            .catch(() => null)
            .finally(() => { if (isMounted) setIsChecking(false); });
        return () => { isMounted = false; };
    }, [router]);

    function handleRequires2FA(token: string) {
        setTempToken(token);
        setStep("totp");
    }

    function handleSuccess() {
        router.push("/feed");
    }

    function handleBack() {
        setTempToken(null);
        setStep("credentials");
    }

    if (isChecking) return <LoginSkeleton className={className} />;

    return (
        <div className={cn("flex flex-col gap-6", className)} {...props}>
            <Card>
                <CardHeader>
                    {step === "credentials" ? (
                        <>
                            <CardTitle>Login to your account</CardTitle>
                            <CardDescription>
                                Enter your email and password to continue
                            </CardDescription>
                        </>
                    ) : (
                        <>
                            <CardTitle>Two-step verification</CardTitle>
                            <CardDescription>
                                Enter the code from your authenticator app to complete login
                            </CardDescription>
                        </>
                    )}
                </CardHeader>
                <CardContent>
                    {step === "credentials" ? (
                        <CredentialsForm
                            onRequires2FA={handleRequires2FA}
                            onSuccess={handleSuccess}
                        />
                    ) : (
                        <TotpForm
                            tempToken={tempToken!}
                            onSuccess={handleSuccess}
                            onBack={handleBack}
                        />
                    )}
                </CardContent>
            </Card>

            {/* Step indicator */}
            <div className="flex justify-center gap-2">
                <span
                    className={cn(
                        "h-1.5 w-6 rounded-full transition-all",
                        step === "credentials" ? "bg-primary" : "bg-muted",
                    )}
                />
                <span
                    className={cn(
                        "h-1.5 w-6 rounded-full transition-all",
                        step === "totp" ? "bg-primary" : "bg-muted",
                    )}
                />
            </div>
        </div>
    );
}
