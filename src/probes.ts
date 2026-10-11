import type { TableInfo } from "./discover.js";
import type { Finding } from "./findings.js";
import { totalFromRange, type Client, type Identity } from "./http.js";
import { sensitiveColumns } from "./sensitive.js";

/*
 * Every probe here only reads. Rows are fetched in small samples to learn
 * column names and value shapes; they are never stored or printed.
 */

export type Read = { status: number; rows: Record<string, unknown>[]; total: number | null; code?: string };

const SAMPLE = 5;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Columns that usually point at the owner of a row. Tried when the schema is hidden. */
const OWNER_GUESSES = ["user_id", "owner_id", "profile_id", "id", "created_by", "author_id", "sender_id", "account_id", "member_id"];

export async function readTable(client: Client, as: Identity, table: string, filter = ""): Promise<Read> {
  const res = await client.get(`/rest/v1/${encodeURIComponent(table)}?select=*&limit=${SAMPLE}${filter}`, as, {
    Prefer: "count=exact",
  });
  const rows = res.status === 200 && Array.isArray(res.body) ? (res.body as Record<string, unknown>[]) : [];
  const code = (res.body as { code?: string } | null)?.code;
  return { status: res.status, rows, total: res.status === 200 ? (totalFromRange(res.headers) ?? rows.length) : null, code };
}

export type TableOutcome = "leak" | "empty" | "denied" | "missing" | "error";

/** Can the public key alone read this table? */
export async function probeAnonRead(
  client: Client,
  anon: Identity,
  table: string,
  info: TableInfo,
): Promise<{ outcome: TableOutcome; finding?: Finding; sample: Record<string, unknown>[] }> {
  const r = await readTable(client, anon, table);
  if (r.status === 404 || r.code === "PGRST205" || r.code === "42P01") return { outcome: "missing", sample: [] };
  if (r.status === 401 || r.status === 403) return { outcome: "denied", sample: [] };
  if (r.status !== 200) return { outcome: "error", sample: [] };
  if (!r.rows.length) return { outcome: "empty", sample: [] };
  const sensitive = sensitiveColumns(r.rows, info.columns);
  return {
    outcome: "leak",
    sample: r.rows,
    finding: {
      id: "table.anon_read",
      severity: sensitive ? "crit" : "warn",
      target: table,
      detail: { rows: r.total ?? r.rows.length, ...(sensitive ? { sensitive } : {}) },
    },
  };
}

/**
 * Can user A read rows that belong to user B?
 *
 * For each column that may hold an owner id, B first reads its own rows
 * (`column = B's id`). If B owns some, A runs the same query. A non-zero
 * result means A sees B's data. If B owns no rows anywhere in the table the
 * test is reported as untested instead of passed.
 */
export async function probeCrossUser(
  client: Client,
  a: Identity,
  b: Identity,
  table: string,
  info: TableInfo,
): Promise<{ outcome: "leak" | "protected" | "untested" | "skipped"; finding?: Finding }> {
  if (!b.userId) return { outcome: "skipped" };
  const bAll = await readTable(client, b, table);
  if (bAll.status !== 200) return { outcome: "skipped" }; // not exposed to signed-in users

  const fromRows = bAll.rows.flatMap((r) => Object.entries(r).filter(([, v]) => typeof v === "string" && UUID.test(v)).map(([k]) => k));
  const known = info.columns.length ? info.columns : Object.keys(bAll.rows[0] ?? {});
  const candidates = [...new Set([...info.uuidColumns, ...fromRows, ...(known.length ? [] : OWNER_GUESSES)])];

  let protectedOn = 0;
  for (const column of candidates) {
    const filter = `&${encodeURIComponent(column)}=eq.${b.userId}`;
    const own = await readTable(client, b, table, filter);
    if (own.status !== 200 || !own.total) continue;
    const seen = await readTable(client, a, table, filter);
    if (seen.status !== 200 || !seen.total) {
      protectedOn++;
      continue;
    }
    // Rows that also carry A's id (a chat between A and B, a shared group) are
    // meant to be visible to A. Only rows with no link to A count as a leak.
    const sharedWithA = seen.rows.length > 0 && seen.rows.every((r) => Object.values(r).includes(a.userId));
    if (sharedWithA) {
      protectedOn++;
      continue;
    }
    const sensitive = sensitiveColumns(own.rows, info.columns);
    return {
      outcome: "leak",
      finding: {
        id: "table.cross_user",
        severity: sensitive ? "crit" : "warn",
        target: table,
        detail: { rows: seen.total, column, ...(sensitive ? { sensitive } : {}) },
      },
    };
  }
  if (protectedOn) return { outcome: "protected" };
  return {
    outcome: "untested",
    finding: { id: "table.cross_user_untested", severity: "info", target: table, detail: {} },
  };
}

const COMMON_BUCKETS = ["avatars", "images", "uploads", "photos", "files", "documents", "public", "media", "attachments"];

async function listBucket(client: Client, as: Identity, bucket: string, prefix = ""): Promise<number | null> {
  const res = await client.post(`/storage/v1/object/list/${encodeURIComponent(bucket)}`, as, {
    prefix,
    limit: 100,
    offset: 0,
    sortBy: { column: "name", order: "asc" },
  });
  return res.status === 200 && Array.isArray(res.body) ? res.body.length : null;
}

/** Can strangers list files? Can A list the folder named after B's id? */
export async function probeStorage(client: Client, ids: { anon: Identity; a?: Identity; b?: Identity }, codeBuckets: Iterable<string>) {
  const findings: Finding[] = [];
  const names = new Set([...codeBuckets, ...COMMON_BUCKETS]);
  for (const as of [ids.anon, ids.a].filter(Boolean) as Identity[]) {
    const res = await client.get("/storage/v1/bucket", as).catch(() => null);
    if (res?.status === 200 && Array.isArray(res.body)) for (const b of res.body as { id?: string }[]) if (b.id) names.add(b.id);
  }

  let checked = 0;
  for (const bucket of names) {
    const anonCount = await listBucket(client, ids.anon, bucket);
    if (anonCount === null) continue; // no such bucket, or no access
    checked++;
    if (anonCount > 0) {
      findings.push({ id: "storage.anon_list", severity: "warn", target: bucket, detail: { files: anonCount === 100 ? "100+" : anonCount } });
      continue;
    }
    if (ids.a && ids.b?.userId) {
      const own = await listBucket(client, ids.b, bucket, ids.b.userId);
      if (!own) continue;
      const seen = await listBucket(client, ids.a, bucket, ids.b.userId);
      if (seen) findings.push({ id: "storage.cross_user", severity: "crit", target: bucket, detail: { files: seen } });
    }
  }
  return { findings, checked };
}

const PRIVILEGED = /delete|remove|admin|grant|role|reset|approve|refund|credit|balance|reward|payout|transfer|set_|update_|ban|promote|purge|wipe/i;

export function rpcFindings(rpcs: string[]): Finding[] {
  return rpcs.map((name) => ({
    id: "rpc.exposed" as const,
    severity: PRIVILEGED.test(name) ? ("warn" as const) : ("info" as const),
    target: name,
    detail: { role: "anon" },
  }));
}

type AuthSettings = { disable_signup?: boolean; mailer_autoconfirm?: boolean; external?: { email?: boolean } };

export async function probeAuth(client: Client, anon: Identity): Promise<Finding[]> {
  const res = await client.get("/auth/v1/settings", anon).catch(() => null);
  if (res?.status !== 200) return [];
  const s = res.body as AuthSettings;
  const findings: Finding[] = [];
  if (!s.disable_signup) {
    findings.push({ id: "auth.signup_open", severity: "info", target: "auth", detail: {} });
    if (s.mailer_autoconfirm && s.external?.email !== false)
      findings.push({ id: "auth.autoconfirm", severity: "warn", target: "auth", detail: {} });
  }
  return findings;
}

/** Signs in a test account with email and password and returns its token. */
export async function signIn(client: Client, anon: Identity, email: string, password: string): Promise<string> {
  const res = await client.post("/auth/v1/token?grant_type=password", anon, { email, password });
  const token = (res.body as { access_token?: string } | null)?.access_token;
  if (res.status !== 200 || !token) throw new Error(`Could not sign in ${email} (HTTP ${res.status}). Check the test account.`);
  return token;
}
