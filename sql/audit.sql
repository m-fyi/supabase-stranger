-- supabase-stranger SQL audit
-- Read-only: it only reads system catalogs. It changes nothing.
-- Run it in the Supabase SQL editor, with psql, or through the Supabase MCP.
-- Each row is one finding: severity, check_id, object, detail.

with tables as (
  select c.oid, n.nspname, c.relname, c.relkind, c.relrowsecurity, c.reloptions,
         has_table_privilege('anon', c.oid, 'SELECT') as anon_read,
         has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') as anon_write,
         has_table_privilege('authenticated', c.oid, 'SELECT') as auth_read,
         has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE') as auth_write
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
),
policies as (
  select p.*, ('anon' = any(p.roles) or 'public' = any(p.roles)) as for_anon,
         (trim(coalesce(p.qual, '')) = 'true' or trim(coalesce(p.with_check, '')) = 'true') as is_true
  from pg_policies p
  where p.schemaname in ('public', 'storage')
),
findings as (
  -- Tables with RLS off that the API roles can reach: the table is wide open.
  select 'crit' as severity, 'sql.rls_disabled' as check_id, nspname || '.' || relname as object,
         'RLS is off; ' || concat_ws(', ',
           case when anon_read then 'anon can read' end,
           case when anon_write then 'anon can write' end,
           case when auth_read then 'signed-in users can read' end,
           case when auth_write then 'signed-in users can write' end) as detail
  from tables
  where relkind in ('r', 'p') and not relrowsecurity and (anon_read or anon_write or auth_read or auth_write)

  union all
  -- Policies that let everyone through.
  select case when cmd <> 'SELECT' and for_anon then 'crit' else 'warn' end,
         'sql.policy_true', schemaname || '.' || tablename,
         format('policy "%s" (%s to %s) allows every row', policyname, cmd, array_to_string(roles, ','))
  from policies
  where permissive = 'PERMISSIVE' and is_true

  union all
  -- Policies for signed-in users that never look at who the user is.
  -- A helper function that checks auth.uid() inside is fine; read it to be sure.
  select 'warn', 'sql.policy_any_user', schemaname || '.' || tablename,
         format('policy "%s" (%s to %s) does not mention auth.uid() or auth.jwt()', policyname, cmd, array_to_string(roles, ','))
  from policies
  where schemaname = 'public' and not is_true
    and ('authenticated' = any(roles) or 'public' = any(roles))
    and coalesce(qual, '') || ' ' || coalesce(with_check, '') !~* 'auth\.(uid|jwt)\(\)'

  union all
  -- Views run as their owner unless security_invoker is set, so they ignore RLS.
  select case when anon_read then 'crit' else 'warn' end, 'sql.view_bypass', nspname || '.' || relname,
         'view without security_invoker: it ignores RLS on the tables it reads'
  from tables
  where relkind = 'v' and (anon_read or auth_read)
    and not exists (select 1 from unnest(coalesce(reloptions, '{}')) o
                    where o in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1'))

  union all
  -- Materialized views have no RLS at all.
  select case when anon_read then 'crit' else 'warn' end, 'sql.matview_exposed', nspname || '.' || relname,
         'materialized view readable through the API; RLS does not apply to it'
  from tables
  where relkind = 'm' and (anon_read or auth_read)

  union all
  -- A view over auth.users publishes emails and phone numbers.
  select 'crit', 'sql.auth_users_exposed', nspname || '.' || relname, 'reads auth.users and is readable through the API'
  from tables
  where relkind in ('v', 'm') and (anon_read or auth_read) and pg_get_viewdef(oid) ilike '%auth.users%'

  union all
  -- SECURITY DEFINER functions skip RLS. The API roles can call them by default.
  select case when has_function_privilege('anon', p.oid, 'EXECUTE') then 'warn' else 'info' end,
         'sql.definer_exposed',
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'SECURITY DEFINER, callable by ' || concat_ws(', ',
           case when has_function_privilege('anon', p.oid, 'EXECUTE') then 'anon' end,
           case when has_function_privilege('authenticated', p.oid, 'EXECUTE') then 'signed-in users' end)
           || '; it must check the caller itself'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef
    and p.prorettype not in ('trigger'::regtype, 'event_trigger'::regtype)
    and (has_function_privilege('anon', p.oid, 'EXECUTE') or has_function_privilege('authenticated', p.oid, 'EXECUTE'))

  union all
  -- SECURITY DEFINER without a fixed search_path can be tricked into using another schema's objects.
  select 'warn', 'sql.definer_no_search_path',
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'SECURITY DEFINER without SET search_path'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) cfg where cfg like 'search_path=%')

  union all
  -- Public buckets: anyone with a file path can download. Fine for avatars, not for documents.
  select 'info', 'sql.storage_public_bucket', 'storage.buckets/' || id, 'public bucket'
  from storage.buckets
  where public
)
select severity, check_id, object, detail
from findings
order by case severity when 'crit' then 0 when 'warn' then 1 else 2 end, check_id, object;
