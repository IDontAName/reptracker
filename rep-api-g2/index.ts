import { createClient } from "jsr:@supabase/supabase-js@2";

// Honor tracker — Group 2. Uses only the g2_* tables; never touches the original group's data.
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const T = { accounts: "g2_accounts", npcs: "g2_npcs", scores: "g2_scores", sessions: "g2_sessions", settings: "g2_settings", notes: "g2_notes", history: "g2_note_history", deletedNpcs: "g2_deleted_npcs", deletedNotes: "g2_deleted_notes" };
const HISTORY_SHOWN = 30; // matches the trim limit in g2_save_note
const NPC_FIELDS = ["name", "role", "grp", "subgroup", "wing", "section", "squad", "year", "signet", "second_signet", "power", "signet_revealed", "status", "deceased", "public_note", "sort_order"];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-session-token",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: CORS }); }

async function hashPassword(password: string, salt?: string): Promise<string> {
  const enc = new TextEncoder();
  const saltBytes = salt ? Uint8Array.from(atob(salt), c => c.charCodeAt(0)) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" }, key, 256);
  return `${btoa(String.fromCharCode(...saltBytes))}:${btoa(String.fromCharCode(...new Uint8Array(bits)))}`;
}
async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  return (await hashPassword(pw, stored.split(":")[0])) === stored;
}
function newToken() { return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/[^a-zA-Z0-9]/g, "").slice(0, 40); }
function clampScore(v: unknown) { const n = parseInt(String(v)); return Number.isFinite(n) ? Math.max(-20, Math.min(20, n)) : 0; }
function cleanStyle(st: any) {
  const font = ["serif", "sans", "mono"].includes(st?.font) ? st.font : "serif";
  const size = Math.max(12, Math.min(28, parseInt(st?.size) || 16));
  const lh = Math.max(1.2, Math.min(2.4, Number(st?.lh) || 1.6));
  return { font, size, lh };
}
function pickNpc(src: any) { const o: any = {}; for (const k of NPC_FIELDS) if (k in src) o[k] = src[k] === "" ? null : src[k]; return o; }

// Two plain queries joined in code (no PostgREST embeds).
async function getMe(token: string | null) {
  if (!token) return null;
  const { data: s } = await admin.from(T.sessions).select("account_id, expires_at").eq("token", token).maybeSingle();
  if (!s || new Date((s as any).expires_at) < new Date()) return null;
  const { data: a } = await admin.from(T.accounts).select("id, character_name, is_dm, must_change_password").eq("id", (s as any).account_id).maybeSingle();
  return a as { id: string; character_name: string; is_dm: boolean; must_change_password: boolean } | null;
}
async function getSettings() {
  const { data } = await admin.from(T.settings).select("key, value");
  const o: Record<string, unknown> = {};
  (data ?? []).forEach((r: any) => { o[r.key] = r.value; });
  return { reveal_first_year_signets: o.reveal_first_year_signets === true };
}
// First years have not been threshed yet: their signets stay hidden from players unless
// the global setting or that NPC's own toggle reveals them. Masking happens here, server-side.
function maskForPlayer(npcs: any[], settings: { reveal_first_year_signets: boolean }) {
  return npcs.map((n) => {
    if (String(n.year ?? "").trim() === "1" && !settings.reveal_first_year_signets && !n.signet_revealed)
      return { ...n, signet: "Unknown", second_signet: "Unknown" };
    return n;
  });
}
async function stateFor(accountId: string, asDm: boolean) {
  const [npcsR, scoresR, settings, notesR] = await Promise.all([
    admin.from(T.npcs).select("*").order("sort_order"),
    admin.from(T.scores).select("npc_id, value").eq("account_id", accountId),
    getSettings(),
    admin.from(T.notes).select("npc_id, body, style, updated_at").eq("account_id", accountId),
  ]);
  const notes: Record<string, unknown> = {};
  (notesR.data ?? []).forEach((n: any) => { notes[n.npc_id] = { body: n.body, style: n.style, updated_at: n.updated_at }; });
  const scores: Record<string, number> = {};
  (scoresR.data ?? []).forEach((s: any) => { scores[s.npc_id] = s.value; });
  const npcs = npcsR.data ?? [];
  return { npcs: asDm ? npcs : maskForPlayer(npcs, settings), scores, notes, settings: asDm ? settings : undefined };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  let payload: any = {};
  try { payload = await req.json(); } catch { /* empty body */ }
  const action = payload.action as string;
  const token = req.headers.get("x-session-token");

  try {
    // ---------- PUBLIC ----------
    if (action === "list_characters") {
      const { data } = await admin.from(T.accounts).select("character_name, is_dm").order("character_name");
      return json({ characters: data ?? [] });
    }
    if (action === "login") {
      const { character_name, password } = payload;
      const { data: acct } = await admin.from(T.accounts).select("*").eq("character_name", character_name).maybeSingle();
      if (!acct) return json({ error: "Unknown character" }, 401);
      if (!(await verifyPassword(String(password ?? ""), (acct as any).password_hash))) return json({ error: "Incorrect password" }, 401);
      const tk = newToken();
      await admin.from(T.sessions).insert({ token: tk, account_id: (acct as any).id });
      return json({ token: tk, character_name: (acct as any).character_name, is_dm: (acct as any).is_dm, must_change_password: !!(acct as any).must_change_password });
    }
    if (action === "logout") {
      if (token) await admin.from(T.sessions).delete().eq("token", token);
      return json({ ok: true });
    }

    // ---------- SIGNED IN ----------
    const me = await getMe(token);
    if (!me) return json({ error: "Not authenticated" }, 401);

    if (action === "me") return json({ character_name: me.character_name, is_dm: me.is_dm, must_change_password: !!me.must_change_password });
    if (action === "change_password") {
      const pw = String(payload.new_password ?? "");
      if (pw.length < 4 || pw.length > 64) return json({ error: "Password must be 4–64 characters" }, 400);
      const { data: cur } = await admin.from(T.accounts).select("password_plain, initial_password").eq("id", me.id).maybeSingle();
      if (me.must_change_password && (pw === (cur as any)?.initial_password)) return json({ error: "Choose a new password, not your start code" }, 400);
      const { error } = await admin.from(T.accounts)
        .update({ password_hash: await hashPassword(pw), password_plain: pw, must_change_password: false }).eq("id", me.id);
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }
    // Until a first-login password change is done, nothing else is allowed.
    if (me.must_change_password) return json({ error: "Password change required", must_change_password: true }, 403);
    if (action === "get_state") return json({ ...(await stateFor(me.id, me.is_dm)), is_dm: me.is_dm });
    if (action === "poll_scores") {
      const { data } = await admin.from(T.scores).select("npc_id, value").eq("account_id", me.id);
      const scores: Record<string, number> = {};
      (data ?? []).forEach((s: any) => { scores[s.npc_id] = s.value; });
      return json({ scores });
    }

    // ---------- PLAYER NOTES (own notes only) ----------
    if (action === "set_note") {
      if (!payload.npc_id) return json({ error: "npc_id required" }, 400);
      // g2_save_note (database function) archives the previous version, saves, and trims history in one transaction.
      const { data, error } = await admin.rpc("g2_save_note", {
        p_account: me.id, p_npc: payload.npc_id, p_body: String(payload.body ?? ""), p_style: cleanStyle(payload.style),
      });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, updated_at: data });
    }
    if (action === "note_history") {
      const { data } = await admin.from(T.history).select("id, body, style, saved_at").eq("account_id", me.id).eq("npc_id", payload.npc_id)
        .order("saved_at", { ascending: false }).limit(HISTORY_SHOWN);
      return json({ history: data ?? [] });
    }

    // ---------- DM ONLY ----------
    if (!me.is_dm) return json({ error: "DM only" }, 403);

    if (action === "preview_as_player") {
      const { data: t } = await admin.from(T.accounts).select("id, character_name").eq("id", payload.target_account_id).maybeSingle();
      if (!t) return json({ error: "Not found" }, 404);
      return json({ ...(await stateFor((t as any).id, false)), is_dm: false, previewing_as: (t as any).character_name });
    }
    if (action === "set_setting") {
      if (payload.key !== "reveal_first_year_signets") return json({ error: "Unknown setting" }, 400);
      const { error } = await admin.from(T.settings).upsert(
        { key: payload.key, value: !!payload.value, updated_at: new Date().toISOString() }, { onConflict: "key" });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, settings: await getSettings() });
    }
    if (action === "dm_notes_for_npc") {
      const [pR, nR] = await Promise.all([
        admin.from(T.accounts).select("id, character_name").eq("is_dm", false).order("character_name"),
        admin.from(T.notes).select("account_id, body, style, updated_at").eq("npc_id", payload.npc_id),
      ]);
      const byAcct: Record<string, any> = {};
      (nR.data ?? []).forEach((n: any) => { byAcct[n.account_id] = n; });
      const notes = (pR.data ?? []).filter((p: any) => byAcct[p.id] && byAcct[p.id].body.trim())
        .map((p: any) => ({ character_name: p.character_name, body: byAcct[p.id].body, style: byAcct[p.id].style, updated_at: byAcct[p.id].updated_at }));
      return json({ notes });
    }
    if (action === "dm_scores_for_npc") {
      const [pR, sR] = await Promise.all([
        admin.from(T.accounts).select("id, character_name").eq("is_dm", false).order("character_name"),
        admin.from(T.scores).select("account_id, value").eq("npc_id", payload.npc_id),
      ]);
      const scores: Record<string, number> = {};
      (sR.data ?? []).forEach((s: any) => { scores[s.account_id] = s.value; });
      return json({ players: pR.data ?? [], scores });
    }
    if (action === "set_score") {
      const { error } = await admin.from(T.scores).upsert(
        { account_id: payload.target_account_id, npc_id: payload.npc_id, value: clampScore(payload.value), updated_at: new Date().toISOString() },
        { onConflict: "account_id,npc_id" });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }
    if (action === "upsert_npc") {
      const n = payload.npc ?? {};
      const row = pickNpc(n);
      if ("deceased" in row) row.status = row.deceased ? "Deceased" : "Active";
      if (n.id) {
        const { error } = await admin.from(T.npcs).update(row).eq("id", n.id);
        if (error) return json({ error: error.message }, 400);
        return json({ ok: true, id: n.id });
      }
      if (!row.name) return json({ error: "Name required" }, 400);
      if (row.sort_order == null) {
        const { data: last } = await admin.from(T.npcs).select("sort_order").order("sort_order", { ascending: false }).limit(1).maybeSingle();
        row.sort_order = ((last as any)?.sort_order ?? 0) + 1;
      }
      const { data, error } = await admin.from(T.npcs).insert(row).select("id").single();
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, id: (data as any).id });
    }
    if (action === "delete_npc") {
      // Details, standings and notes are archived by a trigger first; if archiving fails, nothing is deleted.
      const { error } = await admin.from(T.npcs).delete().eq("id", payload.npc_id);
      if (error) return json({ error: "Not deleted: " + error.message }, 400);
      return json({ ok: true });
    }
    if (action === "list_accounts") {
      const { data } = await admin.from(T.accounts)
        .select("id, character_name, is_dm, created_at, must_change_password, initial_password, password_plain").order("character_name");
      return json({ accounts: data ?? [] });
    }
    if (action === "create_account") {
      const { character_name, password, is_dm } = payload;
      if (!character_name || !password) return json({ error: "Name and password required" }, 400);
      const { data, error } = await admin.from(T.accounts)
        .insert({ character_name, password_hash: await hashPassword(password), is_dm: !!is_dm,
          initial_password: password, password_plain: password, must_change_password: !is_dm }).select("id").single();
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, id: (data as any).id });
    }
    if (action === "update_account") {
      const { target_account_id, character_name, password } = payload;
      const upd: any = {};
      if (character_name) upd.character_name = character_name;
      if (password) { upd.password_hash = await hashPassword(password); upd.password_plain = password; }
      if (!Object.keys(upd).length) return json({ ok: true });
      const { error } = await admin.from(T.accounts).update(upd).eq("id", target_account_id);
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }
    if (action === "reset_password") {
      // Back to the account's start code; the player is asked to choose a new password on next login.
      const { data: t } = await admin.from(T.accounts).select("id, is_dm, initial_password").eq("id", payload.target_account_id).maybeSingle();
      if (!t) return json({ error: "Not found" }, 404);
      if (!(t as any).initial_password) return json({ error: "This account has no start code on record" }, 400);
      const code = (t as any).initial_password;
      const { error } = await admin.from(T.accounts)
        .update({ password_hash: await hashPassword(code), password_plain: code, must_change_password: !(t as any).is_dm }).eq("id", (t as any).id);
      if (error) return json({ error: error.message }, 400);
      await admin.from(T.sessions).delete().eq("account_id", (t as any).id);   // sign them out everywhere
      return json({ ok: true, password: code });
    }
    if (action === "delete_account") {
      if (payload.target_account_id === me.id) return json({ error: "You can't delete your own account" }, 400);
      // Notes are archived by a trigger first; if archiving fails, nothing is deleted.
      const { error } = await admin.from(T.accounts).delete().eq("id", payload.target_account_id);
      if (error) return json({ error: "Not deleted: " + error.message }, 400);
      return json({ ok: true });
    }
    if (action === "export_all") {
      const [npcs, accounts, scores, notes, history, deletedNpcs, deletedNotes] = await Promise.all([
        admin.from(T.npcs).select("*").order("sort_order"),
        admin.from(T.accounts).select("id, character_name, is_dm, created_at"),
        admin.from(T.scores).select("*"),
        admin.from(T.notes).select("*"),
        admin.from(T.history).select("*"),
        admin.from(T.deletedNpcs).select("*").order("deleted_at"),
        admin.from(T.deletedNotes).select("*").order("deleted_at"),
      ]);
      return json({ exported_at: new Date().toISOString(), npcs: npcs.data ?? [], accounts: accounts.data ?? [], scores: scores.data ?? [],
        notes: notes.data ?? [], note_history: history.data ?? [],
        archive: { deleted_npcs: deletedNpcs.data ?? [], deleted_notes: deletedNotes.data ?? [] } });
    }

    return json({ error: "Unknown action: " + action }, 400);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
