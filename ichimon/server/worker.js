// ichimon（一問一答）アカウント同期用 Worker
// KV: USERS
//   user:<id>  -> {salt, hash, created}
//   data:<id>  -> {log:{key:{c,w,l,t}}, updated}
//   tok:<token> -> <id>   (180日で期限切れ)
const ITER = 10000;
const TOKEN_TTL = 60 * 60 * 24 * 180;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...CORS } });
const err = (msg, status = 400) => json({ error: msg }, status);

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
function randHex(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }

async function hashPass(pass, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(saltHex), iterations: ITER }, key, 256);
  return hex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function normId(id) { return String(id || "").trim().toLowerCase(); }
function validId(id) { return /^[a-z0-9_\-]{3,20}$/.test(id); }

function mergeLog(base, inc) {
  const out = Object.assign({}, base);
  for (const k of Object.keys(inc || {})) {
    const a = out[k], b = inc[k];
    if (!b || typeof b !== "object") continue;
    const nb = { c: +b.c || 0, w: +b.w || 0, l: b.l === 1 ? 1 : 0, t: +b.t || 0 };
    if (b.st != null) nb.st = Math.max(0, Math.min(4, +b.st || 0));
    if (b.sb != null) nb.sb = +b.sb || 0;
    if (b.ck) nb.ck = true;
    if (Array.isArray(b.h)) nb.h = b.h.slice(-5).map((e) => [e && e[0] === 1 ? 1 : 0, +(e && e[1]) || 0]);
    if (!a) { out[k] = nb; continue; }
    const na = a.c + a.w, nn = nb.c + nb.w;
    if (nn > na || (nn === na && nb.t > a.t)) out[k] = nb;
  }
  return out;
}

async function issueToken(env, id) {
  const tok = randHex(24);
  await env.USERS.put("tok:" + tok, id, { expirationTtl: TOKEN_TTL });
  return tok;
}
async function authed(req, env) {
  const h = req.headers.get("Authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!/^[0-9a-f]{48}$/.test(tok)) return null;
  return await env.USERS.get("tok:" + tok);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path === "/register" && req.method === "POST") {
        const b = await req.json();
        const id = normId(b.id), pass = String(b.pass || "");
        if (!validId(id)) return err("IDは半角英数字・_・- の3〜20文字にしてください");
        if (pass.length < 4 || pass.length > 64) return err("パスワードは4文字以上にしてください");
        if (await env.USERS.get("user:" + id)) return err("そのIDはすでに使われています", 409);
        const salt = randHex(16);
        await env.USERS.put("user:" + id, JSON.stringify({ salt, hash: await hashPass(pass, salt), created: Date.now() }));
        const log = mergeLog({}, b.log || {});
        await env.USERS.put("data:" + id, JSON.stringify({ log, updated: Date.now() }));
        return json({ id, token: await issueToken(env, id), log });
      }
      if (path === "/login" && req.method === "POST") {
        const b = await req.json();
        const id = normId(b.id), pass = String(b.pass || "");
        const u = JSON.parse((await env.USERS.get("user:" + id)) || "null");
        if (!u || !safeEqual(await hashPass(pass, u.salt), u.hash)) return err("IDかパスワードがちがいます", 401);
        const d = JSON.parse((await env.USERS.get("data:" + id)) || '{"log":{}}');
        const log = mergeLog(d.log || {}, b.log || {});
        await env.USERS.put("data:" + id, JSON.stringify({ log, updated: Date.now() }));
        return json({ id, token: await issueToken(env, id), log });
      }
      if (path === "/data") {
        const id = await authed(req, env);
        if (!id) return err("ログインし直してください", 401);
        const d = JSON.parse((await env.USERS.get("data:" + id)) || '{"log":{}}');
        if (req.method === "GET") return json({ id, log: d.log || {} });
        if (req.method === "PUT") {
          const b = await req.json();
          const log = b.reset ? {} : mergeLog(d.log || {}, b.log || {});
          await env.USERS.put("data:" + id, JSON.stringify({ log, updated: Date.now() }));
          return json({ id, log });
        }
      }
      if (path === "/logout" && req.method === "POST") {
        const h = req.headers.get("Authorization") || "";
        if (h.startsWith("Bearer ")) await env.USERS.delete("tok:" + h.slice(7));
        return json({ ok: true });
      }
      if (path === "/") return json({ ok: true, app: "ichimon-sync" });
      return err("not found", 404);
    } catch (e) {
      return err("server error", 500);
    }
  },
};
