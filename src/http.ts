/** Who a request runs as: the public key alone, or a signed-in user. */
export type Identity = { label: "anon" | "A" | "B"; jwt?: string; userId?: string };

export type Response = { status: number; body: unknown; headers: Headers };

export type Client = {
  url: string;
  rest(path: string, as: Identity, init?: { method?: string; headers?: Record<string, string>; body?: unknown }): Promise<Response>;
  get(path: string, as: Identity, headers?: Record<string, string>): Promise<Response>;
  post(path: string, as: Identity, body: unknown): Promise<Response>;
};

/**
 * Tiny Supabase HTTP client. Works with legacy anon JWT keys and new
 * sb_publishable_ keys (which go in `apikey` only, never as a bearer token).
 * Every request has a timeout; nothing here writes data.
 */
export function createClient(opts: { url: string; key: string; fetch?: typeof fetch; timeoutMs?: number }): Client {
  const base = opts.url.replace(/\/+$/, "");
  const doFetch = opts.fetch ?? fetch;
  const keyIsJwt = opts.key.startsWith("eyJ");

  async function request(path: string, as: Identity, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) {
    const headers: Record<string, string> = { apikey: opts.key, Accept: "application/json", ...init.headers };
    const bearer = as.jwt ?? (keyIsJwt ? opts.key : undefined);
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    const res = await doFetch(`${base}${path}`, {
      method: init.method ?? "GET",
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      /* not JSON; keep the text */
    }
    return { status: res.status, body, headers: res.headers };
  }

  return {
    url: base,
    rest: request,
    get: (path, as, headers) => request(path, as, { headers }),
    post: (path, as, body) => request(path, as, { method: "POST", body }),
  };
}

/** Total from a PostgREST `Content-Range: 0-4/12431` header, if present. */
export function totalFromRange(headers: Headers): number | null {
  const m = /\/(\d+)$/.exec(headers.get("content-range") ?? "");
  return m ? Number(m[1]) : null;
}

/** The `sub` and `role` claims of a JWT, without verifying it. */
export function decodeJwt(jwt: string): { sub?: string; role?: string; ref?: string } | null {
  const part = jwt.split(".")[1];
  if (!part) return null;
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/** Runs `fn` over `items` with at most `limit` in flight. */
export async function pool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  });
  await Promise.all(workers);
  return out;
}
