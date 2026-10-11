# Secret findings

Sections: service-role, public-env, env-committed.

## service-role
A service role JWT or `sb_secret_` key in the code or bundle gives full database access, RLS bypassed. Treat it as already stolen.
1. User rotates it in the dashboard (Project Settings → API Keys). For legacy JWT keys this means rotating the JWT secret, which also changes the anon key: the app needs the new anon key too. You cannot do this step.
2. Remove it from the code. Server code reads it from an env var; client code never needs it.
3. If the repo is shared or public, it stays in git history. Rotation is what makes it harmless.

## public-env
`NEXT_PUBLIC_`, `EXPO_PUBLIC_`, `VITE_`, `REACT_APP_` and similar variables are compiled into the app users download. A secret in one is public. Rename it without the prefix, read it only on the server, and rotate it if it was ever shipped.

## env-committed
An env file is tracked by git. Anyone with the repo, now or later, can read it.
```bash
git rm --cached <file>
echo "<file>" >> .gitignore
```
Rotate every secret that was in it. `crit` means it held a service key.
