# RLS findings

Sections: anon-read, cross-user, rls-disabled, policy-true, views, sql-audit. Read one with
`sed -n '/^## <name>$/,/^## /p' rls.md`.

## anon-read
The public key ships in the app bundle, so this is what anyone on the internet can read. Rows with emails, phones, ids or tokens = breach. Tables meant to be public (published posts, products) are fine if no private column is in them.

Fix, owner-only:
```sql
alter table public.t enable row level security;
create policy "t: owner reads" on public.t for select to authenticated
  using ((select auth.uid()) = user_id);
```
Public on purpose but with private columns: move them to a separate owner-only table, or expose a view with `security_invoker = true` that leaves them out.

Wrap `auth.uid()` in `(select ...)`: Postgres then runs it once per query, not once per row.

## cross-user
User A read rows that belong to user B. The policy checks that someone is signed in (`to authenticated using (true)` or `auth.role() = 'authenticated'`), not who. Since anyone can sign up, this is close to public.

Fix: compare the owner column with the caller.
```sql
drop policy "<broad policy>" on public.t;
create policy "t: owner reads" on public.t for select to authenticated
  using ((select auth.uid()) = user_id);
```
Shared data (chat participants, team members): check membership.
```sql
using (exists (select 1 from public.members m
               where m.team_id = t.team_id and m.user_id = (select auth.uid())))
```
`sql.policy_any_user` can be a false alarm when the policy calls a helper function that checks `auth.uid()` inside. Read the function before changing anything.

`table.cross_user_untested`: B owns no rows there, so nothing was tested. Ask the user to create data with B, then rescan.

## rls-disabled
RLS off + API grants = the table is fully open, writes included. Turning RLS on with no policy blocks all API access, so add the policies the app needs at the same time:
```sql
alter table public.t enable row level security;
-- then one policy per operation the app really uses (select/insert/update/delete)
```
Insert/update policies need `with check ((select auth.uid()) = user_id)`, or users can write rows in someone else's name.

## policy-true
`using (true)` / `with check (true)` lets every row through for the listed roles. Fine for a public read of public data. Never fine for insert/update/delete to anon: anyone can write.

## views
Views run as their owner, so they ignore RLS on the tables they read unless created with `security_invoker` (Postgres 15+):
```sql
alter view public.v set (security_invoker = true);
```
Materialized views have no RLS at all: `revoke select on public.mv from anon, authenticated;` and serve the data another way.
A view over `auth.users` publishes emails and phones. Drop it, or replace it with a `public.profiles` table that holds only what should be visible.

## sql-audit
The REST schema is hidden, so the outside scan only tested tables the code mentions. Run the SQL audit (`npx supabase-stranger sql`): it lists every table, policy, view and function from inside the database.
