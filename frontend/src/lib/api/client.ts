// Server-rendered pages (Server Components) run inside the Next.js server
// process, which in Docker Compose is a *different container* than the one
// `NEXT_PUBLIC_API_URL` (used by the browser) points at — `localhost` there
// would mean "the frontend container", not the backend. `API_INTERNAL_URL`
// is a server-only override (never bundled for the browser) so SSR fetches
// can target the backend's Docker service name while the browser keeps
// using the publicly reachable URL. Falls back to the public URL so
// host-based dev (`npm run dev` outside Docker) is unaffected.
const BASE_URL =
  process.env.API_INTERNAL_URL ??
  process.env.NEXT_PUBLIC_API_URL ??
  "http://localhost:8000/api/v1";

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${await res.text()}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}
