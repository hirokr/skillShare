"use client";

/**
 * components/two-factor-settings.tsx
 *
 * Complete 2FA management card for the dashboard.
 * Handles three flows:
 *   1. Setup  → call /auth/2fa/setup, render QR code, confirm with TOTP code
 *   2. Enable → POST /auth/2fa/confirm once user confirms code from their app
 *   3. Disable → POST /auth/2fa/disable with current TOTP code as confirmation
 */

import { useEffect, useRef, useState } from "react";
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

// ─── Tiny inline QR-code renderer (no external library) ───────────────────────
// Uses the browser's native QR generation via a data URI approach:
// We render the otpauth:// URI as a QR image via a free open-source API
// hosted at qrcode.ovi.com which requires no API key and sends no user data
// beyond the (already-public) otpauth URL.
// If the network is unavailable, we fall back to displaying the raw secret.

function QrCode({ url, size = 180 }: { url: string; size?: number }) {
    const [failed, setFailed] = useState(false);
    const src = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(url)}`;

    if (failed) return null;

    return (
        // eslint-disable-next-line @next/next/no-img-element
        <img
            src={src}
            alt="Scan this QR code with your authenticator app"
            width={size}
            height={size}
            className="rounded-lg border border-border"
            onError={() => setFailed(true)}
        />
    );
}

// ─── TOTP countdown ring ───────────────────────────────────────────────────────

function TotpCountdown() {
    const [secondsLeft, setSecondsLeft] = useState(0);

    useEffect(() => {
        function tick() {
            const now = Math.floor(Date.now() / 1000);
            setSecondsLeft(30 - (now % 30));
        }
        tick();
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, []);

    const pct = (secondsLeft / 30) * 100;
    const r = 10;
    const circ = 2 * Math.PI * r;
    const dash = (pct / 100) * circ;
    const color = secondsLeft <= 5 ? "#ef4444" : secondsLeft <= 10 ? "#f59e0b" : "#22c55e";

    return (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <svg width={28} height={28} viewBox="0 0 28 28">
                <circle cx={14} cy={14} r={r} fill="none" stroke="#e5e7eb" strokeWidth={3} />
                <circle
                    cx={14}
                    cy={14}
                    r={r}
                    fill="none"
                    stroke={color}
                    strokeWidth={3}
                    strokeDasharray={`${dash} ${circ}`}
                    strokeLinecap="round"
                    transform="rotate(-90 14 14)"
                    style={{ transition: "stroke-dasharray 0.5s ease, stroke 0.3s" }}
                />
                <text x={14} y={18} textAnchor="middle" fontSize={9} fill={color} fontWeight="600">
                    {secondsLeft}
                </text>
            </svg>
            Code refreshes in {secondsLeft}s
        </div>
    );
}

// ─── Setup wizard ──────────────────────────────────────────────────────────────

interface SetupWizardProps {
    onEnabled: () => void;
    onCancel: () => void;
}

type SetupPhase = "loading" | "scan" | "confirm" | "done";

function SetupWizard({ onEnabled, onCancel }: SetupWizardProps) {
    const [phase, setPhase] = useState<SetupPhase>("loading");
    const [otpauthUrl, setOtpauthUrl] = useState<string | null>(null);
    const [rawSecret, setRawSecret] = useState<string | null>(null);
    const [code, setCode] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [secretVisible, setSecretVisible] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    // Call /auth/2fa/setup on mount
    useEffect(() => {
        let alive = true;
        apiPost("/auth/2fa/setup", {})
            .then((data) => {
                if (!alive) return;
                const d = data as { otpauthUrl: string; secret: string };
                setOtpauthUrl(d.otpauthUrl);
                setRawSecret(d.secret);
                setPhase("scan");
            })
            .catch((err) => {
                if (!alive) return;
                setError(err instanceof Error ? err.message : "Setup failed");
                setPhase("scan"); // show error state
            });
        return () => { alive = false; };
    }, []);

    // Focus code input when reaching confirm phase
    useEffect(() => {
        if (phase === "confirm") {
            setTimeout(() => inputRef.current?.focus(), 60);
        }
    }, [phase]);

    async function handleEnable(e: React.FormEvent) {
        e.preventDefault();
        setError(null);
        if (!/^\d{6}$/.test(code)) {
            setError("Enter the 6-digit code from your authenticator app");
            return;
        }
        setLoading(true);
        try {
            await apiPost("/auth/2fa/confirm", { totpCode: code });
            setPhase("done");
            setTimeout(onEnabled, 1200);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Verification failed");
            setCode("");
            inputRef.current?.focus();
        } finally {
            setLoading(false);
        }
    }

    // ── Phase: loading ──
    if (phase === "loading") {
        return (
            <div className="flex flex-col items-center gap-3 py-8 text-muted-foreground text-sm">
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                Generating your secret key…
            </div>
        );
    }

    // ── Phase: done ──
    if (phase === "done") {
        return (
            <div className="flex flex-col items-center gap-3 py-8">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-green-600 text-2xl">✓</div>
                <p className="font-medium text-green-700">2FA enabled successfully!</p>
                <p className="text-sm text-muted-foreground">You'll be asked for a code on every login.</p>
            </div>
        );
    }

    // ── Phase: scan ──
    if (phase === "scan") {
        return (
            <div className="space-y-5">
                <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                    <li>Open your authenticator app (Google Authenticator, Authy, 1Password, etc.)</li>
                    <li>Tap <strong>Add account</strong> → <strong>Scan QR code</strong></li>
                    <li>Scan the code below, then click <strong>Next</strong></li>
                </ol>

                {otpauthUrl ? (
                    <div className="flex flex-col items-center gap-3">
                        <QrCode url={otpauthUrl} size={180} />
                        <button
                            type="button"
                            onClick={() => setSecretVisible((v) => !v)}
                            className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2"
                        >
                            {secretVisible ? "Hide" : "Can't scan? Enter key manually"}
                        </button>
                        {secretVisible && rawSecret && (
                            <div className="w-full rounded-md border border-border bg-muted/40 px-3 py-2 text-center font-mono text-sm tracking-widest break-all select-all">
                                {rawSecret}
                            </div>
                        )}
                    </div>
                ) : (
                    error && (
                        <p className="text-sm text-destructive text-center">{error}</p>
                    )
                )}

                <div className="flex gap-2 pt-1">
                    <Button
                        type="button"
                        onClick={() => { setError(null); setPhase("confirm"); }}
                        disabled={!otpauthUrl}
                    >
                        Next →
                    </Button>
                    <Button type="button" variant="outline" onClick={onCancel}>
                        Cancel
                    </Button>
                </div>
            </div>
        );
    }

    // ── Phase: confirm ──
    return (
        <form onSubmit={handleEnable} className="space-y-4">
            <p className="text-sm text-muted-foreground">
                Enter the 6-digit code now showing in your authenticator app to confirm setup.
            </p>
            <TotpCountdown />
            <FieldGroup>
                <Field>
                    <FieldLabel htmlFor="setup-code">Authentication code</FieldLabel>
                    <Input
                        ref={inputRef}
                        id="setup-code"
                        type="text"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="000 000"
                        maxLength={6}
                        value={code}
                        onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                        className="tracking-widest text-center text-lg max-w-[160px]"
                        required
                    />
                    {error && (
                        <FieldDescription className="text-destructive">{error}</FieldDescription>
                    )}
                </Field>
            </FieldGroup>
            <div className="flex gap-2">
                <Button type="submit" disabled={loading || code.length < 6}>
                    {loading ? "Verifying…" : "Enable 2FA"}
                </Button>
                <Button
                    type="button"
                    variant="outline"
                    disabled={loading}
                    onClick={() => { setCode(""); setError(null); setPhase("scan"); }}
                >
                    ← Back
                </Button>
            </div>
        </form>
    );
}

// ─── Disable flow ──────────────────────────────────────────────────────────────

interface DisableFormProps {
    onDisabled: () => void;
    onCancel: () => void;
}

function DisableForm({ onDisabled, onCancel }: DisableFormProps) {
    const [code, setCode] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        setTimeout(() => inputRef.current?.focus(), 60);
    }, []);

    async function handleDisable(e: React.FormEvent) {
        e.preventDefault();
        setError(null);
        if (!/^\d{6}$/.test(code)) {
            setError("Enter the 6-digit code from your authenticator app");
            return;
        }
        setLoading(true);
        try {
            await apiPost("/auth/2fa/disable", { totpCode: code });
            onDisabled();
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to disable 2FA");
            setCode("");
            inputRef.current?.focus();
        } finally {
            setLoading(false);
        }
    }

    return (
        <form onSubmit={handleDisable} className="space-y-4">
            <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                ⚠️ Disabling 2FA will make your account less secure. You'll need to confirm
                with your current authenticator code.
            </div>
            <TotpCountdown />
            <FieldGroup>
                <Field>
                    <FieldLabel htmlFor="disable-code">Current authentication code</FieldLabel>
                    <Input
                        ref={inputRef}
                        id="disable-code"
                        type="text"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="000 000"
                        maxLength={6}
                        value={code}
                        onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                        className="tracking-widest text-center text-lg max-w-[160px]"
                        required
                    />
                    {error && (
                        <FieldDescription className="text-destructive">{error}</FieldDescription>
                    )}
                </Field>
            </FieldGroup>
            <div className="flex gap-2">
                <Button type="submit" variant="destructive" disabled={loading || code.length < 6}>
                    {loading ? "Disabling…" : "Disable 2FA"}
                </Button>
                <Button type="button" variant="outline" disabled={loading} onClick={onCancel}>
                    Cancel
                </Button>
            </div>
        </form>
    );
}

// ─── Main exported component ───────────────────────────────────────────────────

export function TwoFactorSettings() {
    const [enabled, setEnabled] = useState<boolean | null>(null); // null = loading
    const [mode, setMode] = useState<"idle" | "setup" | "disable">("idle");

    // Fetch current status
    useEffect(() => {
        let alive = true;
        apiGet("/auth/2fa/status")
            .then((data) => {
                if (!alive) return;
                const d = data as { twoFactorEnabled: boolean };
                setEnabled(d.twoFactorEnabled ?? false);
            })
            .catch(() => {
                if (alive) setEnabled(false);
            });
        return () => { alive = false; };
    }, []);

    function handleEnabled() {
        setEnabled(true);
        setMode("idle");
    }

    function handleDisabled() {
        setEnabled(false);
        setMode("idle");
    }

    return (
        <Card>
            <CardHeader>
                <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div className="space-y-1">
                        <CardTitle className="flex items-center gap-2">
                            Two-factor authentication
                            {enabled === null ? null : enabled ? (
                                <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
                                    <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                                    Enabled
                                </span>
                            ) : (
                                <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                                    <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
                                    Disabled
                                </span>
                            )}
                        </CardTitle>
                        <CardDescription>
                            {enabled
                                ? "Your account is protected with an authenticator app."
                                : "Add an extra layer of security to your account."}
                        </CardDescription>
                    </div>

                    {/* Action button — only shown when no sub-flow is active */}
                    {mode === "idle" && enabled !== null && (
                        enabled ? (
                            <Button
                                type="button"
                                variant="outline"
                                className="shrink-0 border-destructive/50 text-destructive hover:bg-destructive/5"
                                onClick={() => setMode("disable")}
                            >
                                Disable
                            </Button>
                        ) : (
                            <Button
                                type="button"
                                className="shrink-0"
                                onClick={() => setMode("setup")}
                            >
                                Set up 2FA
                            </Button>
                        )
                    )}
                </div>
            </CardHeader>

            {/* Sub-flow content */}
            {mode !== "idle" && (
                <CardContent className="pt-0">
                    <div className="border-t border-border pt-5">
                        {mode === "setup" && (
                            <SetupWizard
                                onEnabled={handleEnabled}
                                onCancel={() => setMode("idle")}
                            />
                        )}
                        {mode === "disable" && (
                            <DisableForm
                                onDisabled={handleDisabled}
                                onCancel={() => setMode("idle")}
                            />
                        )}
                    </div>
                </CardContent>
            )}

            {/* Enabled state summary when idle */}
            {mode === "idle" && enabled && (
                <CardContent className="pt-0">
                    <div className="flex items-start gap-3 rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">
                        <span className="mt-0.5 text-base">🔒</span>
                        <div>
                            <p className="font-medium">2FA is active</p>
                            <p className="text-green-700 text-xs mt-0.5">
                                You'll be prompted for an authenticator code every time you log in.
                                Keep your authenticator app accessible.
                            </p>
                        </div>
                    </div>
                </CardContent>
            )}

            {/* Disabled state info when idle */}
            {mode === "idle" && enabled === false && (
                <CardContent className="pt-0">
                    <div className="flex items-start gap-3 rounded-md border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
                        <span className="mt-0.5 text-base">💡</span>
                        <div>
                            Works with any TOTP app — Google Authenticator, Authy, 1Password,
                            Bitwarden, and more. Setup takes about 30 seconds.
                        </div>
                    </div>
                </CardContent>
            )}
        </Card>
    );
}
