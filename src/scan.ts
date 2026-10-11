import { discover } from "./discover.js";
import { bySeverity, type Finding } from "./findings.js";
import { createClient, decodeJwt, pool, type Identity } from "./http.js";
import { probeAnonRead, probeAuth, probeCrossUser, probeStorage, rpcFindings } from "./probes.js";
import { scanSource, type SourceScan } from "./source.js";

export type ScanOptions = {
  url: string;
  key: string;
  /** Signed-in test users. Two are needed for the cross-user test. */
  tokens?: { a?: string; b?: string };
  /** Already-run source scan, to reuse its table names and findings. */
  source?: SourceScan;
  /** Project folder to scan, when `source` is not given. */
  src?: string;
  fetch?: typeof fetch;
  concurrency?: number;
};

export type ScanResult = {
  url: string;
  identities: string[];
  schemaSource: string[];
  stats: {
    tables: number;
    anon: { leak: number; empty: number; denied: number; missing: number; error: number };
    crossUser: { leak: number; protected: number; untested: number; skipped: number } | null;
    buckets: number;
    rpcs: number;
    filesRead: number;
  };
  findings: Finding[];
};

const identity = (label: Identity["label"], jwt: string): Identity => ({ label, jwt, userId: decodeJwt(jwt)?.sub });

export async function scan(opts: ScanOptions): Promise<ScanResult> {
  const client = createClient({ url: opts.url, key: opts.key, fetch: opts.fetch });
  const anon: Identity = { label: "anon" };
  const a = opts.tokens?.a ? identity("A", opts.tokens.a) : undefined;
  const b = opts.tokens?.b ? identity("B", opts.tokens.b) : undefined;
  if (a && b && a.userId && a.userId === b.userId) throw new Error("Tokens A and B belong to the same user. Use two different test accounts.");

  const source = opts.source ?? (opts.src ? scanSource(opts.src) : undefined);
  const schema = await discover(client, anon, source?.refs);
  const tables = [...schema.tables.entries()];
  const concurrency = opts.concurrency ?? 4;
  const findings: Finding[] = [...(source?.findings ?? [])];

  if (!schema.source.includes("openapi") && schema.source.length)
    findings.push({ id: "discovery.hidden", severity: "info", target: "tables", detail: { source: schema.source.join("+") } });

  const anonResults = await pool(tables, concurrency, ([name, info]) => probeAnonRead(client, anon, name, info));
  const anonStats = { leak: 0, empty: 0, denied: 0, missing: 0, error: 0 };
  anonResults.forEach((r) => {
    anonStats[r.outcome]++;
    if (r.finding) findings.push(r.finding);
  });

  let crossUser: ScanResult["stats"]["crossUser"] = null;
  if (a && b) {
    crossUser = { leak: 0, protected: 0, untested: 0, skipped: 0 };
    // Tables strangers can already read leak to everyone; no need to test them again.
    const candidates = tables.filter((_, i) => anonResults[i]!.outcome !== "leak" && anonResults[i]!.outcome !== "missing");
    const results = await pool(candidates, concurrency, ([name, info]) => probeCrossUser(client, a, b, name, info));
    for (const r of results) {
      crossUser[r.outcome]++;
      if (r.finding) findings.push(r.finding);
    }
  }

  const storage = await probeStorage(client, { anon, a, b }, source?.refs.buckets ?? []);
  findings.push(...storage.findings, ...rpcFindings(schema.rpcs), ...(await probeAuth(client, anon)));

  return {
    url: client.url,
    identities: ["anon", ...(a ? ["A"] : []), ...(b ? ["B"] : [])],
    schemaSource: schema.source,
    stats: {
      tables: tables.length - anonStats.missing,
      anon: anonStats,
      crossUser,
      buckets: storage.checked,
      rpcs: schema.rpcs.length,
      filesRead: source?.filesRead ?? 0,
    },
    findings: findings.sort(bySeverity),
  };
}
