/**
 * A small fake of the Supabase HTTP API, enough to exercise every probe.
 * Each table decides what a caller sees from (role, user id); the fake then
 * applies `col=eq.value` filters, `limit` and the Content-Range count the
 * way PostgREST does.
 */

type Row = Record<string, unknown>;
type Caller = { role: "anon" | "authenticated"; uid?: string };
type TableDef = { rows: Row[]; columns: Record<string, string>; visible: (c: Caller, row: Row) => boolean | "denied" };
type BucketDef = { files: { name: string; owner?: string }[]; anonList: boolean; ownerOnly: boolean };

export type FakeProject = {
  openapi: boolean;
  graphql?: string[];
  tables: Record<string, TableDef>;
  rpcs?: string[];
  buckets?: Record<string, BucketDef>;
  auth?: Record<string, unknown>;
  users?: Record<string, { password: string; uid: string }>;
};

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
export const jwt = (payload: Record<string, unknown>) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.c2lnbmF0dXJlLXRlc3Q`;
export const ANON_KEY = jwt({ role: "anon", ref: "fakeproject", iss: "supabase" });

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

function caller(req: Request): Caller {
  const bearer = req.headers.get("authorization")?.replace(/^Bearer /, "");
  const claims = bearer ? JSON.parse(Buffer.from(bearer.split(".")[1]!, "base64url").toString()) : { role: "anon" };
  return claims.role === "authenticated" ? { role: "authenticated", uid: claims.sub } : { role: "anon" };
}

export function fakeSupabase(p: FakeProject) {
  const requests: string[] = [];
  const fetchFn = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const req = new Request(input, init);
    const url = new URL(req.url);
    const path = url.pathname;
    requests.push(`${req.method} ${path}${url.search}`);
    if (req.method !== "GET" && req.method !== "POST") throw new Error(`fake refuses ${req.method}: probes must only read`);
    const who = caller(req);

    if (path === "/rest/v1/" && req.method === "GET") {
      if (!p.openapi) return json(401, { message: "OpenAPI is not exposed" });
      const paths: Record<string, unknown> = { "/": {} };
      const definitions: Record<string, unknown> = {};
      for (const [name, t] of Object.entries(p.tables)) {
        paths[`/${name}`] = {};
        definitions[name] = { properties: Object.fromEntries(Object.entries(t.columns).map(([c, format]) => [c, { format }])) };
      }
      for (const fn of p.rpcs ?? []) paths[`/rpc/${fn}`] = {};
      return json(200, { swagger: "2.0", paths, definitions });
    }

    if (path === "/graphql/v1") {
      if (!p.graphql) return json(404, { message: "not found" });
      return json(200, { data: { __schema: { queryType: { fields: p.graphql.map((name) => ({ name })) } } } });
    }

    if (path.startsWith("/rest/v1/") && req.method === "GET") {
      const name = decodeURIComponent(path.slice("/rest/v1/".length));
      const table = p.tables[name];
      if (!table) return json(404, { code: "PGRST205", message: `Could not find the table 'public.${name}'` });
      const results = table.rows.map((r) => table.visible(who, r));
      if (table.rows.length && results.every((r) => r === "denied")) return json(401, { code: "42501", message: `permission denied for table ${name}` });
      let rows = table.rows.filter((_, i) => results[i] === true);
      for (const [k, v] of url.searchParams) {
        if (k === "select" || k === "limit") continue;
        if (!(k in table.columns)) return json(400, { code: "42703", message: `column ${name}.${k} does not exist` });
        const value = v.replace(/^eq\./, "");
        rows = rows.filter((r) => String(r[k]) === value);
      }
      const limit = Number(url.searchParams.get("limit") ?? 1000);
      const page = rows.slice(0, limit);
      return json(200, page, { "content-range": `${page.length ? `0-${page.length - 1}` : "*"}/${rows.length}` });
    }

    if (path === "/storage/v1/bucket") return json(200, []);
    if (path.startsWith("/storage/v1/object/list/")) {
      const bucket = p.buckets?.[decodeURIComponent(path.split("/").pop()!)];
      if (!bucket) return json(400, { statusCode: "404", error: "Bucket not found" });
      const { prefix } = (await req.json()) as { prefix: string };
      const inFolder = bucket.files.filter((f) => (prefix ? f.name.startsWith(`${prefix}/`) : true));
      if (who.role === "anon") return json(200, bucket.anonList ? inFolder : []);
      return json(200, bucket.ownerOnly ? inFolder.filter((f) => f.owner === who.uid) : inFolder);
    }

    if (path === "/auth/v1/settings") return json(200, p.auth ?? { disable_signup: true });
    if (path === "/auth/v1/token") {
      const { email, password } = (await req.json()) as { email: string; password: string };
      const user = p.users?.[email];
      if (!user || user.password !== password) return json(400, { error: "invalid_grant" });
      return json(200, { access_token: jwt({ sub: user.uid, role: "authenticated" }) });
    }
    return json(404, { message: `fake has no route for ${path}` });
  };
  return { fetch: fetchFn as typeof fetch, requests };
}

export const UID_A = "aaaaaaaa-0000-4000-8000-00000000000a";
export const UID_B = "bbbbbbbb-0000-4000-8000-00000000000b";
export const TOKEN_A = jwt({ sub: UID_A, role: "authenticated" });
export const TOKEN_B = jwt({ sub: UID_B, role: "authenticated" });

const signedIn = (c: Caller) => c.role === "authenticated";
const deny = (c: Caller) => (c.role === "anon" ? ("denied" as const) : null);

/** A project with one example of each problem, and some tables that are fine. */
export const leakyProject = (): FakeProject => ({
  openapi: true,
  tables: {
    // Leak: any signed-in user reads every profile, emails included.
    profiles: {
      columns: { id: "uuid", username: "text", email: "text" },
      rows: [
        { id: UID_A, username: "ayse", email: "ayse@example.com" },
        { id: UID_B, username: "mert", email: "mert@example.com" },
      ],
      visible: (c) => deny(c) ?? signedIn(c),
    },
    // Public on purpose, nothing private in it.
    posts: {
      columns: { id: "integer", author_id: "uuid", title: "text" },
      rows: [
        { id: 1, author_id: UID_A, title: "hello" },
        { id: 2, author_id: UID_B, title: "hi" },
      ],
      visible: () => true,
    },
    // Leak: strangers read contact details.
    leads: {
      columns: { id: "integer", name: "text", contact: "text" },
      rows: [{ id: 1, name: "Elif", contact: "+90 555 111 22 33" }],
      visible: () => true,
    },
    // Fine: each user sees only their own notes.
    notes: {
      columns: { id: "integer", user_id: "uuid", body: "text" },
      rows: [
        { id: 1, user_id: UID_A, body: "a" },
        { id: 2, user_id: UID_B, body: "b" },
      ],
      visible: (c, r) => (c.role === "anon" ? false : r.user_id === c.uid),
    },
    // Fine: B wrote to A, so A may see it.
    messages: {
      columns: { id: "integer", sender_id: "uuid", recipient_id: "uuid", body: "text" },
      rows: [{ id: 1, sender_id: UID_B, recipient_id: UID_A, body: "hi A" }],
      visible: (c, r) => (c.role === "anon" ? "denied" : r.sender_id === c.uid || r.recipient_id === c.uid),
    },
    // Untestable: B owns nothing here.
    settings: {
      columns: { user_id: "uuid", theme: "text" },
      rows: [{ user_id: UID_A, theme: "dark" }],
      visible: (c, r) => (c.role === "anon" ? "denied" : r.user_id === c.uid),
    },
  },
  rpcs: ["get_feed", "delete_user"],
  buckets: {
    avatars: { files: [{ name: "a.png" }, { name: "b.png" }, { name: "c.png" }], anonList: true, ownerOnly: false },
    documents: {
      files: [
        { name: `${UID_B}/passport.pdf`, owner: UID_B },
        { name: `${UID_B}/contract.pdf`, owner: UID_B },
      ],
      anonList: false,
      ownerOnly: false,
    },
  },
  auth: { disable_signup: false, mailer_autoconfirm: true, external: { email: true } },
  users: { "a@test.dev": { password: "pw-a", uid: UID_A }, "b@test.dev": { password: "pw-b", uid: UID_B } },
});
