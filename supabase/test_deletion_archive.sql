-- Self-test for the deletion archive. Run in the SQL Editor.
-- It ends by raising an error ON PURPOSE: that rolls everything back, so no test data is kept.
-- The error message is the test report. Expect it to start with "ARCHIVE TEST PASSED".
do $$
declare
  acc uuid; npc1 uuid; npc2 uuid;
  dn record; notes_npc int; notes_acct int; hist_len int; live_left int;
begin
  insert into g2_accounts(character_name, password_hash) values ('ZZ Archive Test', 'x') returning id into acc;
  insert into g2_npcs(name, grp, signet, public_note, sort_order) values ('ZZ Archive NPC', 'Basgiath War College', 'Fire', 'dm note', 99999) returning id into npc1;
  insert into g2_npcs(name, grp, sort_order) values ('ZZ Archive NPC 2', 'Poromiel', 99998) returning id into npc2;
  insert into g2_scores(account_id, npc_id, value) values (acc, npc1, 5);
  perform g2_save_note(acc, npc1, 'v1 text', '{"font":"mono","size":18,"lh":1.6}');
  perform g2_save_note(acc, npc1, 'v2 text', '{"font":"mono","size":18,"lh":1.6}');
  perform g2_save_note(acc, npc2, 'note on npc 2', '{}');

  delete from g2_npcs where id = npc1;        -- should archive NPC details, standing, note + history
  delete from g2_accounts where id = acc;      -- should archive the remaining note (on npc2)

  select * into dn from g2_deleted_npcs where npc_id = npc1;
  select count(*) into notes_npc  from g2_deleted_notes where npc_id = npc1 and reason = 'npc_deleted' and body = 'v2 text';
  select jsonb_array_length(history) into hist_len from g2_deleted_notes where npc_id = npc1;
  select count(*) into notes_acct from g2_deleted_notes where npc_id = npc2 and reason = 'account_deleted' and body = 'note on npc 2';
  select count(*) into live_left  from g2_notes where account_id = acc;

  if dn.npc->>'signet' = 'Fire' and dn.npc->>'public_note' = 'dm note'
     and (dn.standings->0->>'value')::int = 5 and dn.standings->0->>'character_name' = 'ZZ Archive Test'
     and notes_npc = 1 and hist_len = 1 and notes_acct = 1 and live_left = 0 then
    raise exception 'ARCHIVE TEST PASSED (rolled back, nothing kept): npc details ok, standing ok, npc note + % history version ok, account note ok', hist_len;
  else
    raise exception 'ARCHIVE TEST FAILED: npc=% standings=% notes_npc=% hist=% notes_acct=% live_left=%',
      dn.npc->>'name', dn.standings, notes_npc, hist_len, notes_acct, live_left;
  end if;
end $$;
