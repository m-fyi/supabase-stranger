export type Severity = "crit" | "warn" | "info";

export type FindingId =
  | "table.anon_read"
  | "table.cross_user"
  | "table.cross_user_untested"
  | "storage.anon_list"
  | "storage.cross_user"
  | "rpc.exposed"
  | "auth.autoconfirm"
  | "auth.signup_open"
  | "secret.service_role"
  | "secret.sb_secret"
  | "secret.public_env"
  | "secret.env_committed"
  | "function.no_verify_jwt"
  | "discovery.hidden";

export type Finding = {
  id: FindingId;
  severity: Severity;
  /** Table, bucket, function or file the finding is about. */
  target: string;
  /** Short facts, e.g. { rows: 12431, cols: "email,phone" }. Never row values. */
  detail: Record<string, string | number>;
};

type Entry = {
  title: (f: Finding) => string;
  why: string;
  fix: string;
  /** File and section in skill/supabase-security/references. */
  ref: string;
};

const d = (f: Finding, k: string) => {
  const v = f.detail[k] ?? "?";
  return typeof v === "number" ? v.toLocaleString("en-US") : v;
};

/** Plain-language text for every finding. Agents read `ref` for the full fix. */
export const catalog: Record<FindingId, Entry> = {
  "table.anon_read": {
    title: (f) => `Anyone can read ${d(f, "rows")} ${f.detail.rows === 1 ? "row" : "rows"} from "${f.target}"${f.detail.sensitive ? `, including ${f.detail.sensitive}` : ""}`,
    why: "The public key ships inside your app, so anyone can run this query.",
    fix: "Enable RLS and allow reads only to the row's owner, or to signed-in users if the data is meant to be shared.",
    ref: "rls.md#anon-read",
  },
  "table.cross_user": {
    title: (f) => `User A can read ${d(f, "rows")} of user B's rows in "${f.target}" (matched on ${d(f, "column")})${f.detail.sensitive ? `, including ${f.detail.sensitive}` : ""}`,
    why: "Any signed-up stranger can read other people's data. This is the most common RLS bug.",
    fix: "Make the SELECT policy compare the owner column with auth.uid(), not just check that a user is signed in.",
    ref: "rls.md#cross-user",
  },
  "table.cross_user_untested": {
    title: (f) => `Could not test "${f.target}" between users: user B owns no rows in it`,
    why: "Without a row that belongs to B, there is nothing for A to try to read.",
    fix: "Use account B in your app until it creates data in this table, then scan again.",
    ref: "rls.md#cross-user",
  },
  "storage.anon_list": {
    title: (f) => `Anyone can list files in bucket "${f.target}" (${d(f, "files")} seen)`,
    why: "Listing lets a stranger find every uploaded file, even with unguessable names.",
    fix: "Remove broad SELECT policies on storage.objects for this bucket; serve files by known path or signed URL.",
    ref: "storage.md#anon-list",
  },
  "storage.cross_user": {
    title: (f) => `User A can list user B's folder in bucket "${f.target}"`,
    why: "Files stored under a user's id folder are visible to other users.",
    fix: "Limit storage.objects policies with (storage.foldername(name))[1] = auth.uid()::text.",
    ref: "storage.md#cross-user",
  },
  "rpc.exposed": {
    title: (f) => `"${f.target}" can be called by ${d(f, "role")}`,
    why: "Functions in the public schema are callable through the API. A SECURITY DEFINER function skips RLS entirely.",
    fix: "Check auth inside the function, or revoke EXECUTE from anon/authenticated if the app does not call it.",
    ref: "functions.md#rpc",
  },
  "auth.autoconfirm": {
    title: () => "New accounts are confirmed without email verification",
    why: "Anyone can create unlimited accounts with fake addresses, so anything readable by signed-in users is effectively public.",
    fix: "Turn on email confirmation in Authentication settings, and add CAPTCHA to sign-up.",
    ref: "auth.md#autoconfirm",
  },
  "auth.signup_open": {
    title: () => "Anyone can sign up",
    why: "Normal for consumer apps. It means 'signed in' is not a security boundary on its own.",
    fix: "Make sure policies check ownership, not just authentication.",
    ref: "auth.md#signup",
  },
  "secret.service_role": {
    title: (f) => `Service role key in ${f.target}`,
    why: "The service role key bypasses all RLS. Whoever has it owns your database.",
    fix: "Rotate the key now in project settings, remove it from the code, and use it only on a server.",
    ref: "secrets.md#service-role",
  },
  "secret.sb_secret": {
    title: (f) => `Secret API key (sb_secret_) in ${f.target}`,
    why: "Secret keys bypass RLS like the service role key.",
    fix: "Delete this key in project settings, create a new one, and keep it server-side.",
    ref: "secrets.md#service-role",
  },
  "secret.public_env": {
    title: (f) => `Secret-looking variable ${d(f, "name")} is exposed to the client in ${f.target}`,
    why: "NEXT_PUBLIC_, EXPO_PUBLIC_, VITE_ and similar variables are bundled into the app that users download.",
    fix: "Rename it without the public prefix and read it only on the server. Rotate it if it was ever shipped.",
    ref: "secrets.md#public-env",
  },
  "secret.env_committed": {
    title: (f) => `${f.target} is committed to git`,
    why: "Anyone with access to the repo, now or later, can read its values.",
    fix: "Remove it from git (git rm --cached), add it to .gitignore, and rotate the keys inside.",
    ref: "secrets.md#env-committed",
  },
  "function.no_verify_jwt": {
    title: (f) => `Edge Function "${f.target}" accepts calls without a user token`,
    why: "verify_jwt = false is right for webhooks, but then the function must check who is calling.",
    fix: "Keep it only for webhooks that verify a signature; otherwise remove verify_jwt = false.",
    ref: "functions.md#verify-jwt",
  },
  "discovery.hidden": {
    title: (f) => `Table list came from ${d(f, "source")}`,
    why: "The API schema is not public, which is good. Tables the code never mentions were not tested.",
    fix: "Run the SQL audit too; it sees every table from inside the database.",
    ref: "rls.md#sql-audit",
  },
};

const ORDER: Record<Severity, number> = { crit: 0, warn: 1, info: 2 };
export const bySeverity = (a: Finding, z: Finding) => ORDER[a.severity] - ORDER[z.severity] || a.target.localeCompare(z.target);
