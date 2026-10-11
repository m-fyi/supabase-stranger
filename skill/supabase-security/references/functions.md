# Function findings

Sections: rpc, definer, verify-jwt.

## rpc
Functions in `public` are callable through `/rest/v1/rpc/<name>`. Postgres grants EXECUTE to PUBLIC by default, so anon can call new functions. Names like delete_*, admin_*, set_role, refund are flagged for a closer look. Read the function body before deciding.

App never calls it:
```sql
revoke execute on function public.f(args) from public, anon, authenticated;
```
App calls it: check the caller first thing inside.
```sql
if (select auth.uid()) is null then raise exception 'not allowed'; end if;
```

## definer
SECURITY DEFINER runs as the function's owner and skips RLS. That is often the point, so the function must check who is calling and what they may touch. Without `set search_path`, a caller can make it use objects from another schema.
```sql
alter function public.f(args) set search_path = '';
-- then refer to every table with its schema: public.t, auth.users
```
Prefer SECURITY INVOKER unless the function really needs to bypass RLS.

## verify-jwt
`verify_jwt = false` in `supabase/config.toml` lets anyone call the Edge Function without a user token. Correct for webhooks (Stripe, WhatsApp), but then the function must verify the provider's signature (for example Stripe's `constructEventAsync`). Anything else: set it back to true.
