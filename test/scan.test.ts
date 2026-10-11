import { describe, expect, it } from "vitest";
import { scan } from "../src/scan.js";
import { ANON_KEY, fakeSupabase, leakyProject, TOKEN_A, TOKEN_B, UID_A } from "./fake-supabase.js";

const URL_ = "https://fakeproject.supabase.co";
const ids = (r: Awaited<ReturnType<typeof scan>>) => r.findings.map((f) => `${f.severity} ${f.id} ${f.target}`);

describe("scan, as a stranger only", () => {
  it("finds what the public key can read and rates it by what the rows contain", async () => {
    const fake = fakeSupabase(leakyProject());
    const r = await scan({ url: URL_, key: ANON_KEY, fetch: fake.fetch });

    expect(ids(r)).toContain("crit table.anon_read leads");
    expect(r.findings.find((f) => f.target === "leads")!.detail).toEqual({ rows: 1, sensitive: "contact (phone)" });
    expect(ids(r)).toContain("warn table.anon_read posts");
    expect(ids(r)).not.toContain("crit table.anon_read profiles");
    expect(r.stats.anon).toMatchObject({ leak: 2, denied: 3, empty: 1 });
    expect(r.stats.crossUser).toBeNull();
  });

  it("flags listable buckets, risky RPC names and email autoconfirm", async () => {
    const r = await scan({ url: URL_, key: ANON_KEY, fetch: fakeSupabase(leakyProject()).fetch });
    expect(ids(r)).toContain("warn storage.anon_list avatars");
    expect(ids(r)).toContain("warn rpc.exposed delete_user");
    expect(ids(r)).toContain("info rpc.exposed get_feed");
    expect(ids(r)).toContain("warn auth.autoconfirm auth");
  });

  it("never writes: every request is a GET or a read-only POST", async () => {
    const fake = fakeSupabase(leakyProject());
    await scan({ url: URL_, key: ANON_KEY, tokens: { a: TOKEN_A, b: TOKEN_B }, fetch: fake.fetch });
    const posts = fake.requests.filter((r) => r.startsWith("POST"));
    expect(posts.every((r) => /\/graphql\/v1|\/storage\/v1\/object\/list\//.test(r))).toBe(true);
  });
});

describe("scan, with two test users", () => {
  const run = () => scan({ url: URL_, key: ANON_KEY, tokens: { a: TOKEN_A, b: TOKEN_B }, fetch: fakeSupabase(leakyProject()).fetch });

  it("catches a policy that lets any signed-in user read everyone's rows", async () => {
    const r = await run();
    const leak = r.findings.find((f) => f.id === "table.cross_user");
    expect(leak).toMatchObject({ severity: "crit", target: "profiles", detail: { column: "id", rows: 1 } });
    expect(String(leak!.detail.sensitive)).toContain("email");
  });

  it("does not call shared rows a leak, and says which tables it could not test", async () => {
    const r = await run();
    expect(ids(r)).not.toContain("crit table.cross_user messages");
    expect(ids(r)).not.toContain("crit table.cross_user notes");
    expect(ids(r)).toContain("info table.cross_user_untested settings");
    expect(r.stats.crossUser).toMatchObject({ leak: 1, protected: 2, untested: 1 });
  });

  it("catches user A listing user B's folder in storage", async () => {
    expect(ids(await run())).toContain("crit storage.cross_user documents");
  });

  it("refuses two tokens of the same user", async () => {
    await expect(scan({ url: URL_, key: ANON_KEY, tokens: { a: TOKEN_A, b: TOKEN_A }, fetch: fakeSupabase(leakyProject()).fetch })).rejects.toThrow(
      /same user/,
    );
  });

  it("puts critical findings first", async () => {
    const r = await run();
    const order = r.findings.map((f) => f.severity);
    expect(order.indexOf("warn")).toBeGreaterThan(order.lastIndexOf("crit"));
  });
});

describe("scan, when the API schema is hidden", () => {
  it("falls back to table names from the code and still finds the leak", async () => {
    const project = { ...leakyProject(), openapi: false };
    const refs = { tables: new Set(["profiles", "leads", "ghost_table"]), rpcs: new Set<string>(), buckets: new Set<string>() };
    const r = await scan({
      url: URL_,
      key: ANON_KEY,
      tokens: { a: TOKEN_A, b: TOKEN_B },
      source: { refs, findings: [], env: {}, filesRead: 3 },
      fetch: fakeSupabase(project).fetch,
    });
    expect(ids(r)).toContain("crit table.anon_read leads");
    expect(ids(r)).toContain("crit table.cross_user profiles");
    expect(ids(r)).toContain("info discovery.hidden tables");
    expect(r.stats.tables).toBe(2); // ghost_table does not exist
  });

  it("also discovers tables through GraphQL introspection", async () => {
    const project = { ...leakyProject(), openapi: false, graphql: ["leadsCollection", "node"] };
    const r = await scan({ url: URL_, key: ANON_KEY, fetch: fakeSupabase(project).fetch });
    expect(r.schemaSource).toEqual(["graphql"]);
    expect(ids(r)).toContain("crit table.anon_read leads");
  });
});

it("uses user ids from the tokens", async () => {
  const r = await scan({ url: URL_, key: ANON_KEY, tokens: { a: TOKEN_A, b: TOKEN_B }, fetch: fakeSupabase(leakyProject()).fetch });
  expect(r.identities).toEqual(["anon", "A", "B"]);
  expect(UID_A).toMatch(/^aaaa/);
});
