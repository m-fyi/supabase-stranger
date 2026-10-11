import { readFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { beforeAll, describe, expect, it } from "vitest";

/*
 * Runs sql/audit.sql against a real Postgres (PGlite, in-process) that is set
 * up like a Supabase project with one example of each mistake, plus correct
 * tables that must not be reported.
 */

const SETUP = `
create role anon;
create role authenticated;
create schema auth;
create table auth.users (id uuid primary key, email text);
create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
create function auth.role() returns text language sql stable as $$ select 'authenticated'::text $$;
create schema storage;
create table storage.buckets (id text primary key, public boolean not null default false);
create table storage.objects (id serial primary key, bucket_id text, name text);
alter table storage.objects enable row level security;
insert into storage.buckets values ('avatars', true), ('documents', false);

-- Mistake: RLS off.
create table public.leads (id int, email text);
-- Mistake: policy that lets everyone through, and an insert open to anon.
create table public.posts (id int, author_id uuid);
alter table public.posts enable row level security;
create policy "read all" on public.posts for select to anon, authenticated using (true);
create policy "anyone writes" on public.posts for insert to anon with check (true);
-- Mistake: signed-in users read every row.
create table public.profiles (id uuid, email text);
alter table public.profiles enable row level security;
create policy "signed in reads" on public.profiles for select to authenticated using (auth.role() = 'authenticated');
-- Correct: owner only.
create table public.notes (id int, user_id uuid);
alter table public.notes enable row level security;
create policy "owner reads" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
-- Correct: RLS on, no policies (blocked through the API).
create table public.internal (id int);
alter table public.internal enable row level security;
-- Mistake: view that ignores RLS, and one that exposes auth.users.
create view public.notes_view as select * from public.notes;
create view public.safe_view with (security_invoker = true) as select * from public.notes;
create view public.user_emails as select id, email from auth.users;
-- Mistake: materialized view.
create materialized view public.stats as select count(*) from public.notes;
-- Mistake: definer function callable by anon, without search_path.
create function public.delete_everything() returns void language sql security definer as $$ select 1 $$;
-- Correct: definer with search_path, signed-in users only.
create function public.my_count() returns bigint language sql security definer set search_path = '' as $$ select 1::bigint $$;
revoke execute on function public.my_count() from public;
grant execute on function public.my_count() to authenticated;
-- Trigger function: not callable through the API.
create function public.on_signup() returns trigger language plpgsql security definer as $$ begin return new; end $$;
-- Mistake: storage policy that lets everyone list.
create policy "list all" on storage.objects for select to anon using (true);

grant select, insert, update, delete on all tables in schema public to anon, authenticated;
`;

type Row = { severity: string; check_id: string; object: string; detail: string };
let rows: Row[] = [];
const has = (severity: string, check: string, object: string) => rows.some((r) => r.severity === severity && r.check_id === check && r.object === object);
const mentions = (object: string) => rows.filter((r) => r.object === object).map((r) => r.check_id);

beforeAll(async () => {
  const db = new PGlite();
  await db.exec(SETUP);
  rows = (await db.query<Row>(readFileSync("sql/audit.sql", "utf8"))).rows;
}, 60_000);

describe("audit.sql", () => {
  it("finds tables with RLS off", () => {
    expect(has("crit", "sql.rls_disabled", "public.leads")).toBe(true);
    expect(rows.find((r) => r.object === "public.leads")!.detail).toContain("anon can read");
  });

  it("finds policies that allow every row, and rates writes by anon as critical", () => {
    expect(has("warn", "sql.policy_true", "public.posts")).toBe(true);
    expect(has("crit", "sql.policy_true", "public.posts")).toBe(true);
    expect(has("warn", "sql.policy_true", "storage.objects")).toBe(true);
  });

  it("finds policies for signed-in users that never check who they are", () => {
    expect(has("warn", "sql.policy_any_user", "public.profiles")).toBe(true);
  });

  it("finds views and materialized views that skip RLS, and views over auth.users", () => {
    expect(has("crit", "sql.view_bypass", "public.notes_view")).toBe(true);
    expect(has("crit", "sql.matview_exposed", "public.stats")).toBe(true);
    expect(has("crit", "sql.auth_users_exposed", "public.user_emails")).toBe(true);
  });

  it("finds definer functions callable by anon and without search_path", () => {
    expect(has("warn", "sql.definer_exposed", "public.delete_everything()")).toBe(true);
    expect(has("warn", "sql.definer_no_search_path", "public.delete_everything()")).toBe(true);
    expect(has("info", "sql.definer_exposed", "public.my_count()")).toBe(true);
  });

  it("lists public buckets as info", () => {
    expect(has("info", "sql.storage_public_bucket", "storage.buckets/avatars")).toBe(true);
    expect(mentions("storage.buckets/documents")).toEqual([]);
  });

  it("stays quiet about correct setups", () => {
    expect(mentions("public.notes")).toEqual([]);
    expect(mentions("public.internal")).toEqual([]);
    expect(mentions("public.safe_view")).toEqual([]);
    // Not callable through the API, but a definer without search_path is still worth fixing.
    expect(mentions("public.on_signup()")).toEqual(["sql.definer_no_search_path"]);
    expect(mentions("public.my_count()")).toEqual(["sql.definer_exposed"]);
  });

  it("puts critical rows first", () => {
    const sev = rows.map((r) => r.severity);
    expect(sev.indexOf("warn")).toBeGreaterThan(sev.lastIndexOf("crit"));
  });
});
