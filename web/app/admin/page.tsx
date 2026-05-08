"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiGet, apiPost } from "@/lib/api";

// ─── Types ────────────────────────────────────────────────────────────────────

type AdminUser = {
	id: string;
	username: string | null;
	email: string | null;
	contact: string | null;
	role: "user" | "admin";
	isActive: boolean;
	twoFactorEnabled: boolean;
	keyVersion: number;
	keyRotatedAt: string | null;
	lastLoginAt: string | null;
	createdAt: string;
};

type KeyHistoryEntry = {
	_id: string;
	algorithm: string;
	version: number;
	status: string;
	createdAt: string;
	expiresAt: string | null;
	rotatedToVersion: number | null;
};

type Tab = "users" | "keys";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(dateStr: string | null) {
	if (!dateStr) return "—";
	return new Date(dateStr).toLocaleDateString("en-US", {
		year: "numeric",
		month: "short",
		day: "numeric",
	});
}

function relativeTime(dateStr: string | null) {
	if (!dateStr) return "never";
	const diff = Date.now() - new Date(dateStr).getTime();
	const mins = Math.floor(diff / 60000);
	if (mins < 1) return "just now";
	if (mins < 60) return `${mins}m ago`;
	const hrs = Math.floor(mins / 60);
	if (hrs < 24) return `${hrs}h ago`;
	const days = Math.floor(hrs / 24);
	return `${days}d ago`;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Badge({ children, variant }: { children: React.ReactNode; variant: "green" | "red" | "blue" | "amber" | "gray" }) {
	const styles: Record<string, string> = {
		green: "bg-emerald-50 text-emerald-700 ring-emerald-200",
		red: "bg-red-50 text-red-700 ring-red-200",
		blue: "bg-blue-50 text-blue-700 ring-blue-200",
		amber: "bg-amber-50 text-amber-700 ring-amber-200",
		gray: "bg-zinc-100 text-zinc-500 ring-zinc-200",
	};
	return (
		<span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[variant]}`}>
			{children}
		</span>
	);
}

function Spinner() {
	return (
		<div className="flex items-center justify-center py-16">
			<div className="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-700" />
		</div>
	);
}

// ─── Key History Modal ────────────────────────────────────────────────────────

function KeyHistoryModal({ userId, username, onClose }: {
	userId: string;
	username: string | null;
	onClose: () => void;
}) {
	const [history, setHistory] = useState<KeyHistoryEntry[] | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		apiGet(`/admin/keys/history/${userId}`)
			.then((d) => setHistory((d as { history: KeyHistoryEntry[] }).history))
			.catch((e) => setError(e instanceof Error ? e.message : "Failed"));
	}, [userId]);

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
			<div className="w-full max-w-xl rounded-2xl border border-zinc-200 bg-white shadow-2xl">
				<div className="flex items-center justify-between border-b border-zinc-100 px-6 py-4">
					<div>
						<h2 className="text-sm font-semibold text-zinc-900">Key History</h2>
						<p className="text-xs text-zinc-500">{username ?? userId}</p>
					</div>
					<button
						onClick={onClose}
						className="rounded-lg px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600"
					>
						✕ Close
					</button>
				</div>
				<div className="max-h-96 overflow-y-auto px-6 py-4">
					{error && <p className="text-sm text-red-600">{error}</p>}
					{!history && !error && <Spinner />}
					{history && history.length === 0 && (
						<p className="text-sm text-zinc-400">No key history found.</p>
					)}
					{history && history.length > 0 && (
						<table className="w-full text-xs">
							<thead>
								<tr className="text-left text-zinc-400">
									<th className="pb-2 font-medium">Algo</th>
									<th className="pb-2 font-medium">Ver</th>
									<th className="pb-2 font-medium">Status</th>
									<th className="pb-2 font-medium">Created</th>
									<th className="pb-2 font-medium">Expires</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-zinc-50">
								{history.map((entry) => (
									<tr key={entry._id} className="text-zinc-600">
										<td className="py-2 font-mono">{entry.algorithm}</td>
										<td className="py-2">v{entry.version}</td>
										<td className="py-2">
											<Badge variant={
												entry.status === "active" ? "green" :
												entry.status === "archived" ? "gray" : "red"
											}>
												{entry.status}
											</Badge>
										</td>
										<td className="py-2">{fmt(entry.createdAt)}</td>
										<td className="py-2">{fmt(entry.expiresAt)}</td>
									</tr>
								))}
							</tbody>
						</table>
					)}
				</div>
			</div>
		</div>
	);
}

// ─── Rotate / Revoke Modal ────────────────────────────────────────────────────

function KeyActionModal({ userId, username, action, onClose, onDone }: {
	userId: string;
	username: string | null;
	action: "rotate" | "revoke";
	onClose: () => void;
	onDone: (msg: string) => void;
}) {
	const [algorithm, setAlgorithm] = useState<"both" | "RSA" | "ECC">("both");
	const [version, setVersion] = useState("");
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		setError(null);
		setLoading(true);
		try {
			if (action === "rotate") {
				const data = await apiPost(`/admin/keys/rotate/${userId}`, { algorithm }) as { message: string; newKeyVersion: number };
				onDone(`Keys rotated to v${data.newKeyVersion}`);
			} else {
				if (!version || isNaN(Number(version))) {
					setError("Enter a valid version number");
					return;
				}
				await apiPost(`/admin/keys/revoke/${userId}`, {
					algorithm: algorithm === "both" ? "RSA" : algorithm,
					version: Number(version),
				});
				onDone("Key version revoked");
			}
		} catch (err) {
			setError(err instanceof Error ? err.message : "Action failed");
		} finally {
			setLoading(false);
		}
	}

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
			<div className="w-full max-w-sm rounded-2xl border border-zinc-200 bg-white shadow-2xl">
				<div className="flex items-center justify-between border-b border-zinc-100 px-6 py-4">
					<div>
						<h2 className="text-sm font-semibold text-zinc-900 capitalize">{action} Keys</h2>
						<p className="text-xs text-zinc-500">{username ?? userId}</p>
					</div>
					<button onClick={onClose} className="rounded-lg px-2 py-1 text-xs text-zinc-400 hover:bg-zinc-100">✕</button>
				</div>
				<form onSubmit={handleSubmit} className="space-y-4 px-6 py-5">
					{action === "rotate" ? (
						<div>
							<label className="mb-1.5 block text-xs font-medium text-zinc-700">Algorithm</label>
							<div className="flex gap-2">
								{(["both", "RSA", "ECC"] as const).map((opt) => (
									<button
										key={opt}
										type="button"
										onClick={() => setAlgorithm(opt)}
										className={`flex-1 rounded-lg border py-1.5 text-xs font-medium transition-colors ${
											algorithm === opt
												? "border-zinc-900 bg-zinc-900 text-white"
												: "border-zinc-200 text-zinc-600 hover:border-zinc-400"
										}`}
									>
										{opt}
									</button>
								))}
							</div>
						</div>
					) : (
						<>
							<div>
								<label className="mb-1.5 block text-xs font-medium text-zinc-700">Algorithm</label>
								<div className="flex gap-2">
									{(["RSA", "ECC"] as const).map((opt) => (
										<button
											key={opt}
											type="button"
											onClick={() => setAlgorithm(opt)}
											className={`flex-1 rounded-lg border py-1.5 text-xs font-medium transition-colors ${
												algorithm === opt
													? "border-zinc-900 bg-zinc-900 text-white"
													: "border-zinc-200 text-zinc-600 hover:border-zinc-400"
											}`}
										>
											{opt}
										</button>
									))}
								</div>
							</div>
							<div>
								<label className="mb-1.5 block text-xs font-medium text-zinc-700">Version number</label>
								<input
									type="number"
									min={1}
									value={version}
									onChange={(e) => setVersion(e.target.value)}
									placeholder="e.g. 1"
									className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm outline-none focus:border-zinc-400 focus:ring-2 focus:ring-zinc-100"
								/>
							</div>
						</>
					)}

					{action === "revoke" && (
						<div className="rounded-lg bg-amber-50 px-3 py-2.5 text-xs text-amber-700">
							⚠ Content encrypted with this key version will become inaccessible.
						</div>
					)}

					{error && <p className="text-xs text-red-600">{error}</p>}

					<div className="flex gap-2 pt-1">
						<button
							type="submit"
							disabled={loading}
							className={`flex-1 rounded-lg py-2 text-xs font-semibold text-white transition-opacity disabled:opacity-60 ${
								action === "revoke" ? "bg-red-600 hover:bg-red-700" : "bg-zinc-900 hover:bg-zinc-700"
							}`}
						>
							{loading ? "Working…" : action === "rotate" ? "Rotate Keys" : "Revoke Version"}
						</button>
						<button
							type="button"
							onClick={onClose}
							disabled={loading}
							className="rounded-lg border border-zinc-200 px-4 py-2 text-xs font-medium text-zinc-600 hover:bg-zinc-50"
						>
							Cancel
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}

// ─── Users Tab ────────────────────────────────────────────────────────────────

function UsersTab() {
	const [users, setUsers] = useState<AdminUser[]>([]);
	const [pagination, setPagination] = useState({ page: 1, total: 0, totalPages: 1 });
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [actionLoading, setActionLoading] = useState<string | null>(null);
	const [toast, setToast] = useState<string | null>(null);
	const [keyModal, setKeyModal] = useState<{ userId: string; username: string | null; action: "rotate" | "revoke" | "history" } | null>(null);

	const fetchUsers = useCallback((page = 1) => {
		setLoading(true);
		setError(null);
		apiGet(`/admin/users?page=${page}&limit=20`)
			.then((d) => {
				const data = d as { users: AdminUser[]; pagination: typeof pagination };
				setUsers(data.users);
				setPagination(data.pagination);
			})
			.catch((e) => setError(e instanceof Error ? e.message : "Failed to load users"))
			.finally(() => setLoading(false));
	}, []);

	useEffect(() => { fetchUsers(1); }, [fetchUsers]);

	function showToast(msg: string) {
		setToast(msg);
		setTimeout(() => setToast(null), 3000);
	}

	async function handleBanToggle(user: AdminUser) {
		setActionLoading(user.id);
		try {
			const endpoint = user.isActive ? `/admin/users/${user.id}/ban` : `/admin/users/${user.id}/unban`;
			await apiPost(endpoint, {});
			setUsers((prev) => prev.map((u) => u.id === user.id ? { ...u, isActive: !u.isActive } : u));
			showToast(user.isActive ? `${user.username ?? "User"} banned` : `${user.username ?? "User"} unbanned`);
		} catch (e) {
			showToast(e instanceof Error ? e.message : "Action failed");
		} finally {
			setActionLoading(null);
		}
	}

	if (loading) return <Spinner />;
	if (error) return <p className="py-8 text-center text-sm text-red-500">{error}</p>;

	return (
		<>
			{toast && (
				<div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-xl border border-zinc-200 bg-white px-5 py-3 text-xs font-medium text-zinc-700 shadow-lg">
					{toast}
				</div>
			)}

			{keyModal && keyModal.action === "history" && (
				<KeyHistoryModal
					userId={keyModal.userId}
					username={keyModal.username}
					onClose={() => setKeyModal(null)}
				/>
			)}
			{keyModal && (keyModal.action === "rotate" || keyModal.action === "revoke") && (
				<KeyActionModal
					userId={keyModal.userId}
					username={keyModal.username}
					action={keyModal.action}
					onClose={() => setKeyModal(null)}
					onDone={(msg) => { setKeyModal(null); showToast(msg); fetchUsers(pagination.page); }}
				/>
			)}

			<div className="space-y-3">
				<div className="flex items-center justify-between">
					<p className="text-xs text-zinc-500">{pagination.total} total users</p>
					<div className="flex gap-1.5">
						{Array.from({ length: pagination.totalPages }, (_, i) => i + 1).map((p) => (
							<button
								key={p}
								onClick={() => fetchUsers(p)}
								className={`h-7 w-7 rounded-md text-xs font-medium transition-colors ${
									p === pagination.page
										? "bg-zinc-900 text-white"
										: "text-zinc-500 hover:bg-zinc-100"
								}`}
							>
								{p}
							</button>
						))}
					</div>
				</div>

				<div className="overflow-hidden rounded-xl border border-zinc-200">
					<table className="w-full text-sm">
						<thead className="bg-zinc-50">
							<tr className="text-left text-xs font-medium text-zinc-500">
								<th className="px-4 py-3">User</th>
								<th className="px-4 py-3 hidden md:table-cell">Email</th>
								<th className="px-4 py-3">Status</th>
								<th className="px-4 py-3 hidden lg:table-cell">Last login</th>
								<th className="px-4 py-3 hidden lg:table-cell">Joined</th>
								<th className="px-4 py-3 text-right">Actions</th>
							</tr>
						</thead>
						<tbody className="divide-y divide-zinc-100">
							{users.map((user) => (
								<tr key={user.id} className="group bg-white hover:bg-zinc-50/60 transition-colors">
									<td className="px-4 py-3">
										<div className="flex items-center gap-2.5">
											<div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-zinc-100 text-xs font-semibold text-zinc-600">
												{(user.username ?? "?")[0]?.toUpperCase()}
											</div>
											<div>
												<p className="text-xs font-medium text-zinc-800">{user.username ?? <span className="text-zinc-400">unknown</span>}</p>
												<div className="flex items-center gap-1 mt-0.5">
													{user.role === "admin" && <Badge variant="blue">admin</Badge>}
													{user.twoFactorEnabled && <Badge variant="green">2FA</Badge>}
												</div>
											</div>
										</div>
									</td>
									<td className="px-4 py-3 hidden md:table-cell">
										<span className="text-xs text-zinc-500">{user.email ?? "—"}</span>
									</td>
									<td className="px-4 py-3">
										<Badge variant={user.isActive ? "green" : "red"}>
											{user.isActive ? "active" : "banned"}
										</Badge>
									</td>
									<td className="px-4 py-3 hidden lg:table-cell">
										<span className="text-xs text-zinc-400">{relativeTime(user.lastLoginAt)}</span>
									</td>
									<td className="px-4 py-3 hidden lg:table-cell">
										<span className="text-xs text-zinc-400">{fmt(user.createdAt)}</span>
									</td>
									<td className="px-4 py-3">
										<div className="flex items-center justify-end gap-1.5">
											<button
												onClick={() => setKeyModal({ userId: user.id, username: user.username, action: "rotate" })}
												className="rounded-md border border-zinc-200 px-2.5 py-1 text-xs text-zinc-600 hover:border-zinc-400 hover:bg-white transition-colors"
											>
												Rotate keys
											</button>
											<button
												onClick={() => setKeyModal({ userId: user.id, username: user.username, action: "history" })}
												className="rounded-md border border-zinc-200 px-2.5 py-1 text-xs text-zinc-600 hover:border-zinc-400 hover:bg-white transition-colors"
											>
												Key history
											</button>
											<button
												onClick={() => handleBanToggle(user)}
												disabled={actionLoading === user.id}
												className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-50 ${
													user.isActive
														? "border border-red-200 text-red-600 hover:bg-red-50"
														: "border border-emerald-200 text-emerald-700 hover:bg-emerald-50"
												}`}
											>
												{actionLoading === user.id ? "…" : user.isActive ? "Ban" : "Unban"}
											</button>
										</div>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</div>
		</>
	);
}

// ─── Keys Tab ─────────────────────────────────────────────────────────────────

function KeysTab() {
	const [userId, setUserId] = useState("");
	const [history, setHistory] = useState<KeyHistoryEntry[] | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [rotateAlgo, setRotateAlgo] = useState<"both" | "RSA" | "ECC">("both");
	const [rotateLoading, setRotateLoading] = useState(false);
	const [toast, setToast] = useState<string | null>(null);

	function showToast(msg: string) {
		setToast(msg);
		setTimeout(() => setToast(null), 3000);
	}

	async function fetchHistory() {
		if (!userId.trim()) return;
		setLoading(true);
		setError(null);
		setHistory(null);
		try {
			const data = await apiGet(`/admin/keys/history/${userId.trim()}`) as { history: KeyHistoryEntry[] };
			setHistory(data.history);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Failed");
		} finally {
			setLoading(false);
		}
	}

	async function handleRotate() {
		if (!userId.trim()) return;
		setRotateLoading(true);
		try {
			const data = await apiPost(`/admin/keys/rotate/${userId.trim()}`, { algorithm: rotateAlgo }) as { newKeyVersion: number };
			showToast(`Rotated to v${data.newKeyVersion}`);
			fetchHistory();
		} catch (e) {
			showToast(e instanceof Error ? e.message : "Rotation failed");
		} finally {
			setRotateLoading(false);
		}
	}

	return (
		<div className="space-y-6">
			{toast && (
				<div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-xl border border-zinc-200 bg-white px-5 py-3 text-xs font-medium text-zinc-700 shadow-lg">
					{toast}
				</div>
			)}

			<div className="rounded-xl border border-zinc-200 bg-white p-5 space-y-4">
				<h2 className="text-sm font-semibold text-zinc-800">Key lookup by User ID</h2>
				<div className="flex gap-2">
					<input
						type="text"
						value={userId}
						onChange={(e) => setUserId(e.target.value)}
						placeholder="MongoDB user ID (24 hex chars)"
						className="flex-1 rounded-lg border border-zinc-200 px-3 py-2 font-mono text-xs outline-none focus:border-zinc-400 focus:ring-2 focus:ring-zinc-100"
					/>
					<button
						onClick={fetchHistory}
						disabled={!userId.trim() || loading}
						className="rounded-lg bg-zinc-900 px-4 py-2 text-xs font-semibold text-white hover:bg-zinc-700 disabled:opacity-50"
					>
						{loading ? "Loading…" : "Fetch history"}
					</button>
				</div>

				{userId.trim() && (
					<div className="flex items-center gap-2 pt-1">
						<span className="text-xs text-zinc-500">Force rotate:</span>
						{(["both", "RSA", "ECC"] as const).map((opt) => (
							<button
								key={opt}
								onClick={() => setRotateAlgo(opt)}
								className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
									rotateAlgo === opt
										? "border-zinc-900 bg-zinc-900 text-white"
										: "border-zinc-200 text-zinc-600 hover:border-zinc-400"
								}`}
							>
								{opt}
							</button>
						))}
						<button
							onClick={handleRotate}
							disabled={rotateLoading}
							className="ml-auto rounded-lg bg-zinc-800 px-4 py-1.5 text-xs font-semibold text-white hover:bg-zinc-600 disabled:opacity-50"
						>
							{rotateLoading ? "Rotating…" : "Rotate"}
						</button>
					</div>
				)}
			</div>

			{error && <p className="text-sm text-red-500">{error}</p>}

			{history && (
				<div className="rounded-xl border border-zinc-200 overflow-hidden">
					<div className="bg-zinc-50 px-5 py-3 border-b border-zinc-200">
						<p className="text-xs font-semibold text-zinc-700">{history.length} key records</p>
					</div>
					{history.length === 0 ? (
						<p className="px-5 py-6 text-xs text-zinc-400">No key records found for this user.</p>
					) : (
						<table className="w-full text-xs">
							<thead className="text-left text-zinc-500">
								<tr>
									<th className="px-5 py-2.5 font-medium">Algorithm</th>
									<th className="px-5 py-2.5 font-medium">Version</th>
									<th className="px-5 py-2.5 font-medium">Status</th>
									<th className="px-5 py-2.5 font-medium">Created</th>
									<th className="px-5 py-2.5 font-medium">Expires</th>
									<th className="px-5 py-2.5 font-medium">Rotated to</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-zinc-50">
								{history.map((entry) => (
									<tr key={entry._id} className="bg-white text-zinc-600">
										<td className="px-5 py-2.5 font-mono">{entry.algorithm}</td>
										<td className="px-5 py-2.5">v{entry.version}</td>
										<td className="px-5 py-2.5">
											<Badge variant={
												entry.status === "active" ? "green" :
												entry.status === "archived" ? "gray" : "red"
											}>
												{entry.status}
											</Badge>
										</td>
										<td className="px-5 py-2.5">{fmt(entry.createdAt)}</td>
										<td className="px-5 py-2.5">{fmt(entry.expiresAt)}</td>
										<td className="px-5 py-2.5">{entry.rotatedToVersion ? `v${entry.rotatedToVersion}` : "—"}</td>
									</tr>
								))}
							</tbody>
						</table>
					)}
				</div>
			)}
		</div>
	);
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AdminPage() {
	const router = useRouter();
	const [authorized, setAuthorized] = useState<boolean | null>(null);
	const [tab, setTab] = useState<Tab>("users");

	useEffect(() => {
		apiGet("/auth/session")
			.then((d) => {
				const data = d as { role: string };
				if (data?.role === "admin") {
					setAuthorized(true);
				} else {
					setAuthorized(false);
					router.replace("/feed");
				}
			})
			.catch(() => {
				setAuthorized(false);
				router.replace("/auth/login");
			});
	}, [router]);

	if (authorized === null) {
		return (
			<div className="flex min-h-screen items-center justify-center">
				<div className="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-700" />
			</div>
		);
	}

	if (!authorized) return null;

	const tabs: { id: Tab; label: string }[] = [
		{ id: "users", label: "Users" },
		{ id: "keys", label: "Key Management" },
	];

	return (
		<div className="min-h-screen bg-zinc-50">
			{/* Header */}
			<div className="border-b border-zinc-200 bg-white">
				<div className="mx-auto w-full max-w-6xl px-6 py-6">
					<div className="flex items-start justify-between">
						<div>
							<div className="flex items-center gap-2 mb-1">
								<span className="inline-flex items-center rounded-md bg-zinc-900 px-2 py-0.5 text-xs font-semibold text-white">
									ADMIN
								</span>
								<h1 className="text-xl font-semibold text-zinc-900">Control Panel</h1>
							</div>
							<p className="text-sm text-zinc-500">
								Manage users, access control, and cryptographic key lifecycle.
							</p>
						</div>
					</div>

					{/* Tabs */}
					<div className="mt-5 flex gap-1 border-b border-zinc-100 -mb-px">
						{tabs.map((t) => (
							<button
								key={t.id}
								onClick={() => setTab(t.id)}
								className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
									tab === t.id
										? "border-zinc-900 text-zinc-900"
										: "border-transparent text-zinc-500 hover:text-zinc-700"
								}`}
							>
								{t.label}
							</button>
						))}
					</div>
				</div>
			</div>

			{/* Content */}
			<div className="mx-auto w-full max-w-6xl px-6 py-8">
				{tab === "users" && <UsersTab />}
				{tab === "keys" && <KeysTab />}
			</div>
		</div>
	);
}