import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyColumn, sensitiveColumns } from "../src/sensitive.js";
import { scanSource } from "../src/source.js";
import { ANON_KEY, jwt } from "./fake-supabase.js";

const SERVICE_KEY = jwt({ role: "service_role", ref: "fakeproject", iss: "supabase" });

function project(files: Record<string, string>, commit: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), "stranger-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  if (commit.length) {
    const git = (...args: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd: dir, stdio: "ignore" });
    git("init", "-q");
    git("add", "-f", ...commit);
    git("commit", "-qm", "init");
  }
  return dir;
}

describe("scanSource", () => {
  const dir = project(
    {
      "src/db.ts": `
        const { data } = await supabase.from("profiles").select("*");
        await supabase.from('orders').insert(row);
        await supabase.rpc("delete_user", { id });
        await supabase.storage.from("avatars").upload(path, file);
        const admin = createClient(url, "${SERVICE_KEY}");
        const anon = createClient(url, "${ANON_KEY}");`,
      "app/config.ts": "export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;",
      ".env.local": `NEXT_PUBLIC_SUPABASE_URL=https://fakeproject.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_KEY}\nSUPABASE_SERVICE_ROLE_KEY=${SERVICE_KEY}\n`,
      ".env.example": `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_KEY}\n`,
      "server/.env": `SUPABASE_SERVICE_ROLE_KEY=${SERVICE_KEY}\n`,
      "supabase/config.toml": `[functions.stripe-webhook]\nverify_jwt = false\n\n[functions.send-mail]\nverify_jwt = true\n`,
      "node_modules/x/index.js": `supabase.from("from_node_modules")`,
    },
    ["server/.env", "src/db.ts"],
  );
  const s = scanSource(dir);
  const found = s.findings.map((f) => `${f.severity} ${f.id} ${f.target}`);

  it("collects the tables, functions and buckets the code uses", () => {
    expect([...s.refs.tables].sort()).toEqual(["orders", "profiles"]);
    expect([...s.refs.rpcs]).toEqual(["delete_user"]);
    expect([...s.refs.buckets]).toEqual(["avatars"]);
  });

  it("reads the project URL and public key from env files", () => {
    expect(s.env).toEqual({ url: "https://fakeproject.supabase.co", key: ANON_KEY });
  });

  it("flags a hardcoded service role key, masked, and ignores the anon key", () => {
    const hit = s.findings.find((f) => f.id === "secret.service_role")!;
    expect(hit.target).toBe("src/db.ts:6");
    expect(String(hit.detail.key)).toMatch(/^eyJ.{5}…$/);
    expect(found.filter((f) => f.includes("secret.service_role"))).toHaveLength(1);
  });

  it("flags secrets in public env variables", () => {
    expect(found).toContain("crit secret.public_env app/config.ts:1");
  });

  it("does not flag a local server .env, only one committed to git", () => {
    expect(found).not.toContain("crit secret.service_role .env.local:3");
    expect(found).toContain("crit secret.env_committed server/.env");
    expect(found.some((f) => f.includes(".env.example"))).toBe(false);
  });

  it("flags Edge Functions without JWT checks", () => {
    expect(found).toContain("warn function.no_verify_jwt stripe-webhook");
    expect(found.some((f) => f.includes("send-mail"))).toBe(false);
  });
});

describe("classifyColumn", () => {
  it("knows sensitive columns by name", () => {
    expect(classifyColumn("email")).toBe("email");
    expect(classifyColumn("phone_number")).toBe("phone");
    expect(classifyColumn("tc_kimlik_no")).toBe("national id");
    expect(classifyColumn("passport_no")).toBe("national id");
    expect(classifyColumn("password_hash")).toBe("password");
  });

  it("knows them by value shape when the name says nothing", () => {
    expect(classifyColumn("contact", ["+90 555 111 22 33"])).toBe("phone");
    expect(classifyColumn("info", ["elif@example.com"])).toBe("email");
    expect(classifyColumn("note", ["TR330006100519786457841326"])).toBe("payment");
  });

  it("does not over-match ordinary columns", () => {
    for (const name of ["image", "page", "message", "storage_path", "footprint", "created_at", "title"]) expect(classifyColumn(name)).toBeNull();
    expect(classifyColumn("created", ["2026-10-12 10:00:00"])).toBeNull();
    expect(classifyColumn("ref", ["1234567890"])).toBeNull();
  });

  it("summarises a sample of rows", () => {
    expect(sensitiveColumns([{ id: 1, email: "a@b.co", title: "x" }])).toBe("email");
  });
});
