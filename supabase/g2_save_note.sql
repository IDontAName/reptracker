-- Honor Tracker (Group 2): atomic note save.
-- Run once in the Supabase dashboard: SQL Editor → New query → paste → Run.

-- 1. Remove the two test rows left by the live check (DM account, NPC "Nathan Hale").
delete from public.g2_note_history
 where body like '[test] %' and account_id = (select id from public.g2_accounts where character_name = 'DM');
delete from public.g2_notes
 where body like '[test] %' and account_id = (select id from public.g2_accounts where character_name = 'DM');

-- 2. Archive the version being replaced, write the new one, keep the newest 30 history rows.
--    One transaction with a row lock, so concurrent saves of the same note can't interleave.
create or replace function public.g2_save_note(p_account uuid, p_npc uuid, p_body text, p_style jsonb)
returns timestamptz
language plpgsql
security invoker
set search_path = public
as $$
declare
  prev record;
  ts timestamptz := clock_timestamp();
begin
  if length(p_body) > 50000 then
    raise exception 'Note is too long (max 50000 characters)' using errcode = '22001';
  end if;
  select body, style, updated_at into prev from g2_notes
   where account_id = p_account and npc_id = p_npc for update;
  if not found and p_body = '' then
    return null;
  end if;
  if found and prev.body is distinct from p_body and length(prev.body) > 0 then
    insert into g2_note_history(account_id, npc_id, body, style, saved_at)
    values (p_account, p_npc, prev.body, prev.style, prev.updated_at);
    delete from g2_note_history where id in (
      select id from g2_note_history where account_id = p_account and npc_id = p_npc
       order by saved_at desc offset 30);
  end if;
  insert into g2_notes(account_id, npc_id, body, style, updated_at)
  values (p_account, p_npc, p_body, coalesce(p_style, '{}'::jsonb), ts)
  on conflict (account_id, npc_id) do update
    set body = excluded.body, style = excluded.style, updated_at = excluded.updated_at;
  return ts;
end $$;

-- 3. Only the edge function (service role) may call it — not the public API key.
revoke execute on function public.g2_save_note(uuid, uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.g2_save_note(uuid, uuid, text, jsonb) to service_role;
