import { catalog, type Finding, type FindingId, type Severity } from "./findings.js";
import type { ScanResult } from "./scan.js";

export const VERSION = "0.1.0";

const host = (url: string) => url.replace(/^https?:\/\//, "");
const compact = (v: string | number) => String(v).replace(/,\s+/g, ",").replace(/\s*\(/g, "(").replace(/\s+/g, "_");
const shown = (r: ScanResult, verbose: boolean) => r.findings.filter((f) => verbose || f.severity !== "info");

function okLine(r: ScanResult): string {
  const parts = [`anon_denied=${r.stats.anon.denied}`, `anon_empty=${r.stats.anon.empty}`];
  if (r.stats.crossUser) parts.push(`users_apart=${r.stats.crossUser.protected}`, `untested=${r.stats.crossUser.untested}`);
  return parts.join(" ");
}

/**
 * One finding per line, no prose. Built for coding agents: the `ref` points
 * at the one reference file worth reading for that finding, so an agent
 * loads only what it needs.
 */
export function formatAgent(r: ScanResult, verbose = false): string {
  const lines = [
    `supabase-stranger ${VERSION} ${host(r.url)} as=${r.identities.join(",")} tables=${r.stats.tables}(${r.schemaSource.join("+") || "none"}) buckets=${r.stats.buckets} rpc=${r.stats.rpcs} src_files=${r.stats.filesRead}`,
  ];
  for (const f of shown(r, verbose)) {
    const detail = Object.entries(f.detail).map(([k, v]) => `${k}=${compact(v)}`).join(" ");
    lines.push(`${f.severity.toUpperCase()} ${f.id} ${compact(f.target)}${detail ? ` ${detail}` : ""} ref=${catalog[f.id].ref}`);
  }
  lines.push(`OK ${okLine(r)}`);
  const hidden = r.findings.length - shown(r, verbose).length;
  if (hidden) lines.push(`INFO ${hidden} hidden, add --verbose`);
  if (!r.stats.crossUser) lines.push("NEXT add --token-a and --token-b (two test users) for the cross-user test");
  lines.push("NEXT run the SQL audit: npx supabase-stranger sql");
  return lines.join("\n");
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint(31), yellow = paint(33), green = paint(32), dim = paint(2), bold = paint(1);

const HEADINGS: Record<Severity, string> = { crit: red("✖ CRITICAL"), warn: yellow("▲ WARNING"), info: dim("· INFO") };

/** Grouped by severity, with why it matters and what to do. */
export function formatHuman(r: ScanResult, verbose = false): string {
  const out: string[] = [bold(`\nsupabase-stranger · ${host(r.url)}`) + dim(` · tested as ${r.identities.join(", ")}\n`)];
  for (const sev of ["crit", "warn", "info"] as Severity[]) {
    const list = shown(r, verbose).filter((f) => f.severity === sev);
    if (!list.length) continue;
    out.push(`${HEADINGS[sev]} (${list.length})`);
    for (const f of list) {
      const c = catalog[f.id];
      out.push(`  ${c.title(f)}`, dim(`    Why: ${c.why}`), dim(`    Fix: ${c.fix}`), "");
    }
  }
  const crit = r.findings.filter((f) => f.severity === "crit").length;
  if (!crit) out.push(green("✓ No critical findings."));
  const s = r.stats;
  out.push(
    dim(`  Tables that refuse strangers: ${s.anon.denied}. Tables that return them nothing: ${s.anon.empty}.`) +
      (s.crossUser ? dim(` Keep users apart: ${s.crossUser.protected}. Could not be tested: ${s.crossUser.untested}.`) : ""),
  );
  if (!s.crossUser) out.push(dim("  Add --token-a and --token-b (two test accounts) to test whether users can read each other's data."));
  out.push(dim("  Next: run the SQL audit for what the outside can't see: npx supabase-stranger sql\n"));
  return out.join("\n");
}

export function formatJson(r: ScanResult): string {
  return JSON.stringify(
    { version: VERSION, ...r, findings: r.findings.map((f) => ({ ...f, title: catalog[f.id].title(f), ref: catalog[f.id].ref })) },
    null,
    2,
  );
}

const TEMPLATES: Partial<Record<FindingId, string>> = {
  "table.anon_read": `alter table public.<table> enable row level security;
-- Owner-only. For data meant for all signed-in users use: to authenticated using (true)
create policy "<table>: owner reads" on public.<table>
  for select to authenticated using ((select auth.uid()) = <owner_column>);`,
  "table.cross_user": `drop policy "<the broad select policy>" on public.<table>;
create policy "<table>: owner reads" on public.<table>
  for select to authenticated using ((select auth.uid()) = <owner_column>);`,
  "storage.anon_list": `-- Remove the broad SELECT policy on storage.objects for this bucket, then:
create policy "<bucket>: owner lists" on storage.objects for select to authenticated
  using (bucket_id = '<bucket>' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
  "storage.cross_user": `create policy "<bucket>: owner lists" on storage.objects for select to authenticated
  using (bucket_id = '<bucket>' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
  "rpc.exposed": `-- If the app never calls it:
revoke execute on function public.<function> from anon, authenticated;
-- If it must stay callable, check the caller first thing inside it:
--   if (select auth.uid()) is null then raise exception 'not allowed'; end if;`,
};

/** A prompt to paste into Claude Code or Cursor, with only the fixes that apply. */
export function formatFixPrompt(r: ScanResult): string {
  const list = r.findings.filter((f) => f.severity !== "info");
  const ids = [...new Set(list.map((f) => f.id))];
  return `# Fix these Supabase security findings

supabase-stranger scanned ${host(r.url)} as ${r.identities.join(", ")} on ${new Date().toISOString().slice(0, 10)}.

Rules:
- Write each database fix as a new SQL migration. Do not apply it to production until I approve it.
- Never disable RLS or widen access to make an error go away.
- Owner checks compare a column with \`(select auth.uid())\`. Being signed in is not enough on its own.
- If a table is meant to be public (for example published posts), say so and leave it, but make sure it has no private columns.
- Rotate any leaked key in the Supabase dashboard before removing it from the code.
- When done, run \`npx supabase-stranger\` again and show me the result.

## Findings

${list.map((f, i) => `${i + 1}. **[${f.severity.toUpperCase()}] ${catalog[f.id].title(f)}**\n   ${catalog[f.id].why} ${catalog[f.id].fix}`).join("\n")}
${ids.some((id) => TEMPLATES[id]) ? `\n## Starting points\n\n${ids.filter((id) => TEMPLATES[id]).map((id) => `For ${id}:\n\n\`\`\`sql\n${TEMPLATES[id]}\n\`\`\``).join("\n\n")}\n` : ""}
Also run the SQL audit (\`npx supabase-stranger sql\`) inside the database. It finds policies, views and functions this outside scan cannot see.
`;
}
