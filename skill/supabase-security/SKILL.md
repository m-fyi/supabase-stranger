---
name: supabase-security
description: Audit and fix a Supabase project's security the way an attacker would see it. Runs supabase-stranger (read-only scan with the public key, two-user cross-read test, source scan for leaked keys) and a read-only SQL audit, explains each finding in plain words, and writes fixes as migrations. Use this whenever the user asks whether their Supabase app is secure, mentions RLS, row level security, policies, leaked or exposed data, the anon or service role key, storage buckets, "can users see each other's data", a pre-launch or security check, or has an AI-built (Lovable, Bolt, Cursor, Claude Code) app on Supabase, even if they don't say "audit".
---

# Supabase security

Goal: show the user what a stranger can read or do in their Supabase project, then close it. Two lenses:
- **Outside** (`npx supabase-stranger`): real requests with the public key, as anon and as two test users. Proves what leaks.
- **Inside** (`sql/audit.sql`): catalog query. Sees policies, views and functions the outside can't.

Both only read. Only scan projects the user owns or may test.

## 1. Gather

- **URL + public key.** The CLI finds them in `.env*` files on its own. Otherwise, with the Supabase MCP: `get_project_url` + `get_publishable_keys`. Use the anon or publishable key. Never pass a service role or `sb_secret_` key; it bypasses RLS and every table would look leaked (the CLI refuses it anyway).
- **Two test users (strongly recommended).** Most real leaks are "any signed-in user reads everyone's rows", and only this test catches it. Ask the user for two accounts that have *not* interacted in the app (no chats, follows, shared groups), each with some data of its own. They set, in their shell or `.env`, never in chat: `SUPABASE_USER_A_EMAIL`, `SUPABASE_USER_A_PASSWORD`, and the same for `B`. Tokens work too: `SUPABASE_TOKEN_A` / `_B`.

## 2. Scan from outside

```bash
npx supabase-stranger --format agent --src .
```

One line per finding: `SEVERITY id target key=value... ref=file.md#section`. `OK` and `NEXT` lines summarise. Exit code 1 means critical findings; that is expected, not a crash.

## 3. Audit from inside

Get the query with `npx supabase-stranger sql`, then run it:
- Supabase MCP: `execute_sql` with the query text. It only reads catalogs.
- Or `psql "$DATABASE_URL" -f <file>`.

Rows: `severity, check_id, object, detail`. If neither route is available, say so and continue with the outside results.

## 4. Read only what you need

Each finding points to one section in `references/`. Read just that section, not the whole file:

```bash
sed -n '/^## anon-read$/,/^## /p' references/rls.md
```

| Finding ids | Section |
|---|---|
| `table.anon_read` | rls.md `anon-read` |
| `table.cross_user`, `table.cross_user_untested`, `sql.policy_any_user` | rls.md `cross-user` |
| `sql.rls_disabled` | rls.md `rls-disabled` |
| `sql.policy_true` | rls.md `policy-true` |
| `sql.view_bypass`, `sql.matview_exposed`, `sql.auth_users_exposed` | rls.md `views` |
| `storage.anon_list`, `storage.cross_user`, `sql.storage_public_bucket` | storage.md `anon-list` / `cross-user` / `public-bucket` |
| `rpc.exposed`, `sql.definer_exposed`, `sql.definer_no_search_path` | functions.md `rpc` / `definer` |
| `function.no_verify_jwt` | functions.md `verify-jwt` |
| `auth.autoconfirm`, `auth.signup_open` | auth.md `autoconfirm` / `signup` |
| `secret.*` | secrets.md `service-role` / `public-env` / `env-committed` |

Skip sections for findings that did not appear. That is where the token savings come from.

## 5. Report

Lead with impact, in plain words, worst first. One line each, no preamble:

```
CRIT  Anyone can read 12,431 profiles with emails and phones.
CRIT  Any signed-up user can read every message.
WARN  Bucket "avatars" lists all files.
OK    19 tables refuse strangers. 5 keep users apart.
```

Merge outside and inside findings about the same object into one line (e.g. `table.anon_read profiles` + `sql.rls_disabled public.profiles` → one line, cause: RLS off). Before calling a table public by mistake, check whether it is meant to be public (published posts, a product catalog); if so, only flag private columns in it.

## 6. Fix

- Write database fixes as a new migration file (`supabase/migrations/<timestamp>_security_fixes.sql`). Show it before applying. Apply to production only after the user says so, even if `apply_migration` is available. A wrong policy can lock real users out.
- Never "fix" by disabling RLS, granting more, or using the service key in the client.
- Leaked keys: the user rotates them in the dashboard first (you can't). Then remove them from the code and from git history if the repo is shared.
- Code fixes (keys in client code, `verify_jwt`) go in the normal code, with the reason in a comment.

## 7. Verify

Run steps 2 and 3 again. Show the before/after in one line per fixed finding. Anything still `untested` needs user B to create data first; say which table.
