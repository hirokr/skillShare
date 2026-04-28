const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000/api";

type ApiOptions = {
	method?: string;
	body?: unknown;
	headers?: Record<string, string>;
};

export async function apiRequest(path: string, options: ApiOptions = {}) {
	const { method = "GET", body, headers = {} } = options;
	const response = await fetch(`${API_BASE}${path}`, {
		method,
		headers: {
			"Content-Type": "application/json",
			...headers,
		},
		credentials: "include",
		body: body ? JSON.stringify(body) : undefined,
	});

	let data: unknown = null;
	try {
		data = await response.json();
	} catch {
		data = null;
	}

	if (!response.ok) {
		const message =
			typeof data === "object" && data && "message" in data
				? String((data as { message?: string }).message)
				: "Request failed";
		throw new Error(message);
	}

	if (typeof window !== "undefined" && path.startsWith("/auth/logout")) {
		window.sessionStorage.removeItem("adminMode");
	}

	return data;
}

export function apiGet(path: string) {
	return apiRequest(path, { method: "GET" });
}

export function apiPost(path: string, body: unknown) {
	return apiRequest(path, { method: "POST", body });
}

export function apiPatch(path: string, body: unknown) {
	return apiRequest(path, { method: "PATCH", body });
}
