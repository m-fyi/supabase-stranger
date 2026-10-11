import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "./findings.js";
import { decodeJwt } from "./http.js";

export type SourceRefs = { tables: Set<string>; rpcs: Set<string>; buckets: Set<string> };

export type SourceScan = {
  refs: SourceRefs;
  findings: Finding[];
  /** SUPABASE_URL and anon/publishable key found in env files, if any. */
  env: { url?: string; key?: string };
  filesRead: number;
};

const SKIP_DIRS = new Set(["node_modules", ".git", ".turbo", ".expo", "Pods", "DerivedData", ".vercel", "coverage", ".cache"]);
const CODE = /\.(m?[jt]sx?|cjs|vue|svelte|astro|dart|swift|kt|py|rb|go|sql|toml|json|html)$/;
const ENV_FILE = /^\.env(\..+)?$/;
const MAX_BYTES = 2_000_000;

const mask = (secret: string) => `${secret.slice(0, 8)}…`;

function* walk(dir: string, depth = 0): Generator<string> {
  if (depth > 12) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const path = join(dir, name);
    let st;
    try {
      st = statSync(path);
    } catch {
      continue;
    }
    if (st.isDirectory()) yield* walk(path, depth + 1);
    else if (st.size <= MAX_BYTES && (CODE.test(name) || ENV_FILE.test(name))) yield path;
  }
}

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

/**
 * Reads a project folder. Finds the tables, functions and buckets the code
 * uses, secrets that should not be there, Edge Functions that skip JWT
 * checks, and env files committed to git. Secrets are masked in findings.
 */
export function scanSource(root: string): SourceScan {
  const refs: SourceRefs = { tables: new Set(), rpcs: new Set(), buckets: new Set() };
  const findings: Finding[] = [];
  const env: SourceScan["env"] = {};
  const seenSecrets = new Set<string>();
  let filesRead = 0;

  for (const path of walk(root)) {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    filesRead++;
    const rel = relative(root, path);
    const isEnv = ENV_FILE.test(path.split("/").pop()!);
    const isExample = /example|sample|template/i.test(rel);

    for (const m of text.matchAll(/storage\s*\.from\(\s*["'`]([\w.-]+)["'`]/g)) refs.buckets.add(m[1]!);
    for (const m of text.matchAll(/(?<!storage\s*)\.from\(\s*["'`]([\w-]+)["'`]\s*\)/g)) refs.tables.add(m[1]!);
    for (const m of text.matchAll(/\.rpc\(\s*["'`]([\w-]+)["'`]/g)) refs.rpcs.add(m[1]!);

    if (isEnv && !isExample) {
      for (const m of text.matchAll(/^\s*(?:export\s+)?\w*SUPABASE_URL\s*=\s*["']?([^"'\s#]+)/gm)) env.url ??= m[1];
      for (const m of text.matchAll(/^\s*(?:export\s+)?\w*SUPABASE_(?:ANON|PUBLISHABLE)(?:_DEFAULT)?_KEY\s*=\s*["']?([^"'\s#]+)/gm)) env.key ??= m[1];
    }

    // A server-side .env holding the service key is normal. Env files only
    // count when committed (committedEnvFiles) or for public-prefixed names.
    if (!isExample && !isEnv) {
      for (const m of text.matchAll(/eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}/g)) {
        if (seenSecrets.has(m[0]) || decodeJwt(m[0])?.role !== "service_role") continue;
        seenSecrets.add(m[0]);
        findings.push({ id: "secret.service_role", severity: "crit", target: `${rel}:${lineOf(text, m.index)}`, detail: { key: mask(m[0]) } });
      }
      for (const m of text.matchAll(/sb_secret_[\w-]{16,}/g)) {
        if (seenSecrets.has(m[0])) continue;
        seenSecrets.add(m[0]);
        findings.push({ id: "secret.sb_secret", severity: "crit", target: `${rel}:${lineOf(text, m.index)}`, detail: { key: mask(m[0]) } });
      }
    }

    if (!isExample) {
      for (const m of text.matchAll(/\b((?:NEXT_PUBLIC|EXPO_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC)_\w*(?:SERVICE_ROLE|SECRET|PRIVATE)\w*)/g)) {
        const key = `${rel}:${m[1]}`;
        if (seenSecrets.has(key)) continue;
        seenSecrets.add(key);
        findings.push({ id: "secret.public_env", severity: "crit", target: `${rel}:${lineOf(text, m.index)}`, detail: { name: m[1]! } });
      }
    }

    if (rel.endsWith("supabase/config.toml") || rel === "config.toml") {
      for (const m of text.matchAll(/\[functions\.([\w-]+)\][^[]*?verify_jwt\s*=\s*false/g)) {
        findings.push({ id: "function.no_verify_jwt", severity: "warn", target: m[1]!, detail: { file: rel } });
      }
    }
  }

  findings.push(...committedEnvFiles(root));
  return { refs, findings, env, filesRead };
}

function committedEnvFiles(root: string): Finding[] {
  let tracked: string;
  try {
    tracked = execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return []; // not a git repo
  }
  return tracked
    .split("\n")
    .filter((f) => ENV_FILE.test(f.split("/").pop() ?? "") && !/example|sample|template/i.test(f))
    .map((f): Finding => {
      let text = "";
      try {
        text = readFileSync(join(root, f), "utf8");
      } catch {
        /* deleted locally but still tracked */
      }
      const holdsSecret =
        /sb_secret_[\w-]{16,}/.test(text) ||
        [...text.matchAll(/eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}/g)].some((m) => decodeJwt(m[0])?.role === "service_role");
      return { id: "secret.env_committed", severity: holdsSecret ? "crit" : "warn", target: f, detail: holdsSecret ? { holds: "service key" } : {} };
    });
}
