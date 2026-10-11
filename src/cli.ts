#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createClient, decodeJwt } from "./http.js";
import { signIn } from "./probes.js";
import { formatAgent, formatFixPrompt, formatHuman, formatJson, VERSION } from "./report.js";
import { scan } from "./scan.js";
import { scanSource } from "./source.js";

const HELP = `supabase-stranger ${VERSION}
See your Supabase the way a stranger does. Read-only.

Usage
  npx supabase-stranger [options]     scan a project
  npx supabase-stranger sql           print the SQL audit to run inside the database

Options
  --url <url>           Project URL        (or SUPABASE_URL, or found in .env files)
  --key <key>           Public anon or publishable key (or SUPABASE_ANON_KEY, or found in .env files)
  --src <dir>           Project folder to scan for table names and leaked keys (default: .)
  --no-src              Skip the source scan
  --token-a <jwt>       Test user A's access token  (or SUPABASE_TOKEN_A, or SUPABASE_USER_A_EMAIL + _PASSWORD)
  --token-b <jwt>       Test user B's access token  (same for B). A and B enable the cross-user test.
  --format <f>          human (default), agent (one line per finding, for AI agents) or json
  --fix-prompt <file>   Write a ready-to-paste fix prompt for Claude Code or Cursor
  --fail-on <level>     Exit 1 on crit (default), warn, or never
  --verbose             Also show info findings

Only scan projects you own or are allowed to test.`;

function fail(message: string): never {
  console.error(`supabase-stranger: ${message}`);
  process.exit(2);
}

const env = process.env;
const firstEnv = (...names: string[]) => names.map((n) => env[n]).find(Boolean);

async function userToken(label: "A" | "B", flag: string | undefined, url: string, key: string): Promise<string | undefined> {
  const token = flag ?? env[`SUPABASE_TOKEN_${label}`];
  if (token) return token;
  const email = env[`SUPABASE_USER_${label}_EMAIL`];
  const password = env[`SUPABASE_USER_${label}_PASSWORD`];
  if (!email || !password) return undefined;
  return signIn(createClient({ url, key }), { label: "anon" }, email, password);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      url: { type: "string" },
      key: { type: "string" },
      src: { type: "string" },
      "no-src": { type: "boolean" },
      "token-a": { type: "string" },
      "token-b": { type: "string" },
      format: { type: "string" },
      "fix-prompt": { type: "string" },
      "fail-on": { type: "string" },
      verbose: { type: "boolean" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });

  if (values.help) return console.log(HELP);
  if (values.version) return console.log(VERSION);
  if (positionals[0] === "sql") {
    const here = dirname(fileURLToPath(import.meta.url));
    return process.stdout.write(readFileSync(join(here, "..", "sql", "audit.sql"), "utf8"));
  }
  if (positionals.length) fail(`unknown command "${positionals[0]}". Try --help.`);

  const format = values.format ?? "human";
  if (!["human", "agent", "json"].includes(format)) fail(`--format must be human, agent or json`);
  const failOn = values["fail-on"] ?? "crit";
  if (!["crit", "warn", "never"].includes(failOn)) fail(`--fail-on must be crit, warn or never`);

  const source = values["no-src"] ? undefined : scanSource(values.src ?? ".");
  const url = values.url ?? firstEnv("SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL", "EXPO_PUBLIC_SUPABASE_URL", "VITE_SUPABASE_URL") ?? source?.env.url;
  const key =
    values.key ??
    firstEnv("SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "EXPO_PUBLIC_SUPABASE_ANON_KEY", "VITE_SUPABASE_ANON_KEY") ??
    source?.env.key;
  if (!url || !key) fail("need the project URL and public key. Pass --url and --key, or run inside a project with a .env file.");
  if (!/^https?:\/\//.test(url)) fail(`--url should look like https://<ref>.supabase.co`);
  if (key.startsWith("sb_secret_") || decodeJwt(key)?.role === "service_role")
    fail("that is a secret key. It bypasses RLS, so everything would look leaked. Use the public anon or publishable key.");

  const [a, b] = await Promise.all([userToken("A", values["token-a"], url, key), userToken("B", values["token-b"], url, key)]);
  if (Boolean(a) !== Boolean(b)) console.error("supabase-stranger: the cross-user test needs both user A and user B; skipping it.");

  const result = await scan({ url, key, source, tokens: a && b ? { a, b } : undefined });

  const output = format === "agent" ? formatAgent(result, values.verbose) : format === "json" ? formatJson(result) : formatHuman(result, values.verbose);
  console.log(output);
  if (values["fix-prompt"]) {
    writeFileSync(values["fix-prompt"], formatFixPrompt(result));
    if (format === "human") console.error(`Fix prompt written to ${values["fix-prompt"]}`);
  }

  const worst = result.findings.some((f) => f.severity === "crit") ? "crit" : result.findings.some((f) => f.severity === "warn") ? "warn" : "none";
  if ((failOn === "crit" && worst === "crit") || (failOn === "warn" && worst !== "none")) process.exitCode = 1;
}

main().catch((error) => fail(error instanceof Error ? error.message : String(error)));
