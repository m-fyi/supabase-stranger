<div align="center">

# supabase-stranger

**See your Supabase the way a stranger does.**

One command shows what anyone can read with the key that ships inside your app, and what one user can read of another's.

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Read-only](https://img.shields.io/badge/scan-read--only-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Tests](https://img.shields.io/badge/tests-31%20passing-brightgreen)

[Run it](#run-it) · [What it finds](#what-it-finds) · [Use it with your AI](#use-it-with-your-ai)

</div>

---

## This keeps happening

In 2025, a researcher scanned 1,645 apps built with an AI app builder. **170 of them, about 1 in 10, let anyone read their database** with just the public key: emails, addresses, payment records, API keys. It became [CVE-2025-48757](https://cvemon.intruder.io/cves/CVE-2025-48757) ([write-up](https://www.superblocks.com/blog/lovable-rls-breach)).

The cause is almost always the same: Row Level Security is off, or a policy checks *that* a user is signed in instead of *who* they are. AI coding tools write these mistakes fast, and they look fine until someone else looks.

This tool is that someone else, before a stranger gets there.

## Run it

Inside your project folder:

```bash
npx supabase-stranger
```

It finds your project URL and public key in your `.env` files. Then it scans:

```
✖ CRITICAL (3)
  Anyone can read 1,204 rows from "leads", including email, phone
  User A can read 3 of user B's rows in "profiles" (matched on id), including email
  Service role key in web/admin.ts:4

▲ WARNING (2)
  Anyone can list files in bucket "avatars" (100+ seen)
  New accounts are confirmed without email verification

  Tables that refuse strangers: 19. Keep users apart: 5.
```

Every finding comes with why it matters and how to fix it.

**Want to try it first?** There's a deliberately leaky demo:

```bash
git clone https://github.com/m-fyi/supabase-stranger && cd supabase-stranger && npm install
npm run demo:server                                  # terminal 1
npx tsx src/cli.ts --src examples/demo-app           # terminal 2
```

## The test most scanners skip

Most real leaks aren't "anyone can read". They're **"any signed-in user can read everyone's rows"**. Since anyone can sign up, that's nearly the same thing.

Give it two test accounts and it checks exactly that:

```bash
SUPABASE_USER_A_EMAIL=a@you.dev SUPABASE_USER_A_PASSWORD=... \
SUPABASE_USER_B_EMAIL=b@you.dev SUPABASE_USER_B_PASSWORD=... \
npx supabase-stranger
```

User B reads its own rows. User A tries the same query. If A gets B's rows, you have a leak. Rows that are meant to be shared, like a chat between A and B, are not counted.

## What it finds

| Where | What |
|---|---|
| **Tables** | Readable with the public key, rated by what's inside (emails, phones, IBANs, tokens) |
| **Between users** | User A reading user B's rows, or listing B's files |
| **Storage** | Buckets anyone can list |
| **Functions** | Risky RPCs anyone can call |
| **Auth** | Sign-ups confirmed without email verification |
| **Your code** | Service role or `sb_secret_` keys in the frontend, secrets in `NEXT_PUBLIC_` / `EXPO_PUBLIC_` / `VITE_` variables, committed `.env` files, Edge Functions with `verify_jwt = false` |
| **Inside the database** | `npx supabase-stranger sql` prints a read-only audit: RLS off, `using (true)` policies, policies that never check `auth.uid()`, views that skip RLS, views over `auth.users`, `security definer` functions without `search_path` |

## Safe by design

- **Read-only.** It never inserts, updates, deletes or calls your functions.
- **Never prints your data.** It reports column names and row counts, never values. Leaked keys are masked.
- **Refuses secret keys.** A service role key would make everything look leaked, so it won't run with one.
- **Only scan projects you own** or are allowed to test.

## Use it with your AI

**Install the skill:**

```bash
npx supabase-stranger skill
```

Then ask Claude Code: *"Is my Supabase app secure?"* It runs the scan, runs the SQL audit through the Supabase MCP, explains each finding in plain words, writes the fixes as a migration, waits for your OK, and scans again to prove they worked.

It's built to spend few tokens. `--format agent` prints one line per finding, and each line points to the one reference section the agent needs to read:

```
CRIT table.cross_user profiles rows=1 column=id sensitive=email ref=rls.md#cross-user
```

**Or hand it a prompt.** `--fix-prompt fixes.md` writes a ready-to-paste prompt with your findings and SQL starting points.

## In CI

```bash
npx supabase-stranger --format agent --fail-on crit
```

Exits with 1 when something critical is found. `--format json` gives the full result.

<details>
<summary><b>All options</b></summary>

```
--url <url>           Project URL (or SUPABASE_URL, or found in .env files)
--key <key>           Public anon or publishable key (or SUPABASE_ANON_KEY, or found in .env files)
--src <dir>           Project folder to scan (default: .)
--no-src              Skip the source scan
--token-a / --token-b Test users' access tokens (or SUPABASE_TOKEN_A/B,
                      or SUPABASE_USER_A_EMAIL + _PASSWORD and the same for B)
--format <f>          human (default), agent or json
--fix-prompt <file>   Write a fix prompt for Claude Code or Cursor
--fail-on <level>     crit (default), warn or never
--verbose             Also show info findings
```

</details>

<details>
<summary><b>How it works</b></summary>

1. **Find the tables** the way an outsider would: the REST API's schema if it's public, GraphQL introspection, and every `.from("…")`, `.rpc("…")` and `storage.from("…")` in your code.
2. **Read each table** as anon with `limit=5` and an exact count. Column names and value shapes decide how sensitive it is.
3. **Cross-user test:** for every column that may hold an owner id, B reads `column = B's id`. If B owns rows and A gets any of them back, and those rows don't involve A, it's a leak.
4. **Storage:** list each bucket as anon, then list B's folder as A.
5. **SQL audit:** one catalog query, tested against a real Postgres in the test suite.

</details>

---

<div align="center">

**If it caught something, give it a ⭐ so the next person finds it before a stranger does.**

MIT · Built by [Melih İlkay Deniz](https://github.com/m-fyi)

</div>
