import { createClient } from "jsr:@supabase/supabase-js@2";

// Honor tracker — Group 2. Uses only the g2_* tables; never touches the original group's data.
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const T = { accounts: "g2_accounts", npcs: "g2_npcs", scores: "g2_scores", sessions: "g2_sessions", settings: "g2_settings" };
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
function pickNpc(src: any) { const o: any = {}; for (const k of NPC_FIELDS) if (k in src) o[k] = src[k] === "" ? null : src[k]; return o; }

// Two plain queries joined in code (no PostgREST embeds).
async function getMe(token: string | null) {
  if (!token) return null;
  const { data: s } = await admin.from(T.sessions).select("account_id, expires_at").eq("token", token).maybeSingle();
  if (!s || new Date((s as any).expires_at) < new Date()) return null;
  const { data: a } = await admin.from(T.accounts).select("id, character_name, is_dm").eq("id", (s as any).account_id).maybeSingle();
  return a as { id: string; character_name: string; is_dm: boolean } | null;
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
  const [npcsR, scoresR, settings] = await Promise.all([
    admin.from(T.npcs).select("*").order("sort_order"),
    admin.from(T.scores).select("npc_id, value").eq("account_id", accountId),
    getSettings(),
  ]);
  const scores: Record<string, number> = {};
  (scoresR.data ?? []).forEach((s: any) => { scores[s.npc_id] = s.value; });
  const npcs = npcsR.data ?? [];
  return { npcs: asDm ? npcs : maskForPlayer(npcs, settings), scores, settings: asDm ? settings : undefined };
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
      return json({ token: tk, character_name: (acct as any).character_name, is_dm: (acct as any).is_dm });
    }
    if (action === "logout") {
      if (token) await admin.from(T.sessions).delete().eq("token", token);
      return json({ ok: true });
    }

    // ---------- SIGNED IN ----------
    const me = await getMe(token);
    if (!me) return json({ error: "Not authenticated" }, 401);

    if (action === "me") return json({ character_name: me.character_name, is_dm: me.is_dm });
    if (action === "get_state") return json({ ...(await stateFor(me.id, me.is_dm)), is_dm: me.is_dm });
    if (action === "poll_scores") {
      const { data } = await admin.from(T.scores).select("npc_id, value").eq("account_id", me.id);
      const scores: Record<string, number> = {};
      (data ?? []).forEach((s: any) => { scores[s.npc_id] = s.value; });
      return json({ scores });
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
      await admin.from(T.npcs).delete().eq("id", payload.npc_id);
      return json({ ok: true });
    }
    if (action === "list_accounts") {
      const { data } = await admin.from(T.accounts).select("id, character_name, is_dm, created_at").order("character_name");
      return json({ accounts: data ?? [] });
    }
    if (action === "create_account") {
      const { character_name, password, is_dm } = payload;
      if (!character_name || !password) return json({ error: "Name and password required" }, 400);
      const { data, error } = await admin.from(T.accounts)
        .insert({ character_name, password_hash: await hashPassword(password), is_dm: !!is_dm }).select("id").single();
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true, id: (data as any).id });
    }
    if (action === "update_account") {
      const { target_account_id, character_name, password } = payload;
      const upd: any = {};
      if (character_name) upd.character_name = character_name;
      if (password) upd.password_hash = await hashPassword(password);
      if (!Object.keys(upd).length) return json({ ok: true });
      const { error } = await admin.from(T.accounts).update(upd).eq("id", target_account_id);
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }
    if (action === "delete_account") {
      if (payload.target_account_id === me.id) return json({ error: "You can't delete your own account" }, 400);
      await admin.from(T.accounts).delete().eq("id", payload.target_account_id); // scores + sessions cascade
      return json({ ok: true });
    }
    if (action === "export_all") {
      const [npcs, accounts, scores] = await Promise.all([
        admin.from(T.npcs).select("*").order("sort_order"),
        admin.from(T.accounts).select("id, character_name, is_dm, created_at"),
        admin.from(T.scores).select("*"),
      ]);
      return json({ exported_at: new Date().toISOString(), npcs: npcs.data ?? [], accounts: accounts.data ?? [], scores: scores.data ?? [] });
    }

    return json({ error: "Unknown action: " + action }, 400);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
