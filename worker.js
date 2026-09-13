/**
 * ProxyCollector —— 代理收集与订阅分发 Worker（单文件，公开仓库版）
 *
 * 上传：
 *   POST /api/proxies            body 每行一条（或 JSON {"proxies":[...]}）→ 永久存储
 *   POST /api/proxies/expiring   同上，但默认 7 天过期（ProxyScrape 试用代理专用路径）
 *   POST /api/proxies?ttl=48h    相对 TTL（s/m/h/d）；?expire=2026-10-01T00:00:00Z 绝对过期时间
 *   认证：Authorization: Bearer <UPLOAD_TOKEN>；管理面板会话亦可上传
 *   支持格式：http/socks5/https URI、vmess://、vless://、ss://、trojan://、
 *             host:port:user:pass、user:pass@host:port、host:port、
 *             sing-box JSON（{"outbounds":[...]}，content-type: application/json）
 *
 * 订阅：GET /sub/<id>?key=<key> —— 按 User-Agent 自动适配：
 *   clash/mihomo/stash/verge → Clash YAML；其余 → base64 URI 列表
 *
 * 过期：每条代理带 expires_at（null=永久）；读取时懒过滤 + cron 硬清理
 * 管理：/admin 面板（登录/订阅管理/代理池/前端提交）
 *
 * KV 绑定 env.PROXY_KV：
 *   p:<sha1(raw)> → JSON {raw, added_at, expires_at, proto?, host?, port?}
 *   sub:<id>      → JSON {id, name, key, created_at, expires_at, enabled}
 * Secrets：UPLOAD_TOKEN、ADMIN_PASSWORD
 */

const DEFAULT_TTL_MS = 7 * 86400 * 1000; // /expiring 路径的默认时长

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------
async function sha1Hex(s) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function jsonResp(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function b64encode(s) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

function b64decode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

/** 相对时间解析：48h / 7d / 30m / 90s → ms；无效返回 null */
function parseRelativeTtl(s) {
  const m = String(s || "").trim().match(/^(\d+)\s*([smhd])$/i);
  if (!m) return null;
  const mult = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2].toLowerCase()];
  return parseInt(m[1], 10) * mult;
}

/** 解析过期参数 → expires_at (ms) 或 null（永久）；非法返回 undefined（报错） */
export function resolveExpire(url) {
  const ttl = url.searchParams.get("ttl");
  const expire = url.searchParams.get("expire");
  const days = url.searchParams.get("expire_days");
  if (ttl) {
    const ms = parseRelativeTtl(ttl);
    if (ms === null) return undefined;
    return Date.now() + ms;
  }
  if (expire) {
    const t = Date.parse(expire);
    return isNaN(t) ? undefined : t;
  }
  if (days) {
    const n = parseInt(days, 10);
    if (isNaN(n) || n <= 0) return undefined;
    return Date.now() + n * 86400000;
  }
  return null; // 无参数 → 永久
}

// ---------------------------------------------------------------------------
// 代理解析：多格式 → 统一记录 {raw, proto?, host?, port?, name?}
//   所有格式保留原始行（raw）用于 base64 URI 订阅直出；
//   能结构化的额外提取字段用于 Clash YAML 转换。
// ---------------------------------------------------------------------------
function b64maybe(s) {
  try {
    const d = b64decode(s);
    return /[\{:"@]/.test(d) || /^[a-z0-9+\/=]+$/i.test(s) === false ? d : null;
  } catch {
    return null;
  }
}

export function parseProxyLine(line) {
  line = line.trim();
  if (!line || line.startsWith("#") || line.startsWith("//")) return null;
  const rec = { raw: line };

  // ---- URI 系 ----
  if (line.startsWith("vmess://")) {
    rec.proto = "vmess";
    try {
      const j = JSON.parse(b64decode(line.slice(8)));
      rec.host = j.add;
      rec.port = parseInt(j.port, 10) || parseInt(j.port, 16);
      rec.name = j.ps || j.remark || j.add;
      rec.vmess = j; // Clash 转换需要完整字段
    } catch {}
    return rec.port ? rec : null;
  }
  if (line.startsWith("vless://")) {
    rec.proto = "vless";
    try {
      const u = new URL(line);
      rec.host = u.hostname;
      rec.port = parseInt(u.port, 10);
      rec.name = decodeURIComponent(u.hash.slice(1)) || u.hostname;
      rec.vless = { uuid: u.username, params: Object.fromEntries(u.searchParams) };
    } catch {}
    return rec.host && rec.port ? rec : null;
  }
  if (line.startsWith("ss://")) {
    rec.proto = "ss";
    try {
      const noScheme = line.slice(5);
      const hashIdx = noScheme.indexOf("#");
      const main = hashIdx >= 0 ? noScheme.slice(0, hashIdx) : noScheme;
      if (hashIdx >= 0) rec.name = decodeURIComponent(noScheme.slice(hashIdx + 1));
      // 形态 A：ss://base64(method:pass@host:port)
      if (!main.includes("@")) {
        const dec = b64decode(main);
        const mm = dec.match(/^(.+?):(.+)@(\[[^\]]+\]|[^:]+):(\d+)$/);
        if (mm) {
          rec.ss = { method: mm[1], password: mm[2] };
          rec.host = mm[3];
          rec.port = parseInt(mm[4], 10);
        }
      } else {
        // 形态 B：ss://base64(method:pass)@host:port
        const at = main.lastIndexOf("@");
        const userinfo = b64decode(main.slice(0, at));
        const mm = userinfo.match(/^(.+?):(.+)$/);
        const hostport = main.slice(at + 1).match(/^(\[[^\]]+\]|[^:]+):(\d+)/);
        if (mm && hostport) {
          rec.ss = { method: mm[1], password: mm[2] };
          rec.host = hostport[1];
          rec.port = parseInt(hostport[2], 10);
        }
      }
    } catch {}
    return rec.host && rec.port ? rec : null;
  }
  if (line.startsWith("trojan://")) {
    rec.proto = "trojan";
    try {
      const u = new URL(line);
      rec.host = u.hostname;
      rec.port = parseInt(u.port, 10);
      rec.trojan = { password: decodeURIComponent(u.username) };
      rec.name = decodeURIComponent(u.hash.slice(1)) || u.hostname;
    } catch {}
    return rec.host && rec.port ? rec : null;
  }

  // ---- http / socks5 / https URI ----
  const uriMatch = line.match(
    /^(https?|socks5h?):\/\/(\[[^\]]+\]|[^:@/]+)(?::([^@]*))?@(\[[^\]]+\]|[^:/]+):(\d+)\/?$/i
  );
  if (uriMatch) {
    const [, proto, user, pass, host, port] = uriMatch;
    rec.proto = proto.toLowerCase();
    rec.host = host;
    rec.port = parseInt(port, 10);
    rec.user = user ? decodeURIComponent(user) : "";
    rec.pass = pass ? decodeURIComponent(pass) : "";
    return rec;
  }

  // ---- 纯文本系 ----
  let m = line.match(/^(\[[^\]]+\]|[^:]+):(\d+):([^:]+):(.+)$/);
  if (m) {
    Object.assign(rec, { proto: "http", host: m[1], port: +m[2], user: m[3], pass: m[4] });
    return rec;
  }
  m = line.match(/^([^:@]+):([^@]+)@(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (m) {
    Object.assign(rec, { proto: "http", host: m[3], port: +m[4], user: m[1], pass: m[2] });
    return rec;
  }
  m = line.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (m) {
    Object.assign(rec, { proto: "http", host: m[1], port: +m[2], user: "", pass: "" });
    return rec;
  }

  return null;
}

/** sing-box JSON outbounds → 记录列表 */
export function parseSingBox(body) {
  try {
    const data = JSON.parse(body);
    const outbounds = data.outbounds || (Array.isArray(data) ? data : []);
    const out = [];
    for (const o of outbounds) {
      if (!o.server || !o.server_port) continue;
      if (["direct", "block", "dns"].includes(o.type)) continue;
      const rec = {
        raw: JSON.stringify(o),
        proto: o.type,
        host: o.server,
        port: o.server_port,
      };
      if (o.type === "http" || o.type === "socks") {
        rec.user = o.username || "";
        rec.pass = o.password || "";
        rec.proto = o.type === "socks" ? "socks5" : "http";
      }
      if (o.type === "vmess") rec.vmess = { add: o.server, port: o.server_port, id: o.uuid, scy: o.security, net: o.transport };
      if (o.type === "vless") rec.vless = { uuid: o.uuid, params: {} };
      if (o.type === "shadowsocks") rec.ss = { method: o.method, password: o.password };
      if (o.type === "trojan") rec.trojan = { password: o.password };
      out.push(rec);
    }
    return out;
  } catch {
    return null;
  }
}

export function parseUploadBody(body, contentType) {
  const recs = [];
  const seen = new Set();
  const push = (rec) => {
    if (!rec) return;
    const h = rec.raw.trim();
    if (seen.has(h)) return;
    seen.add(h);
    recs.push(rec);
  };
  if (contentType && contentType.includes("application/json")) {
    let data;
    try {
      data = JSON.parse(body);
    } catch {
      return null;
    }
    if (data && (data.outbounds || Array.isArray(data))) {
      // sing-box outbounds
      for (const rec of parseSingBox(body) || []) push(rec);
      return recs;
    }
    const arr = Array.isArray(data) ? data : data.proxies || [];
    for (const item of arr) {
      if (typeof item === "object" && item.raw) push(item);
      else push(parseProxyLine(String(item)));
    }
    return recs;
  }
  for (const line of body.split(/\r?\n/)) push(parseProxyLine(line));
  return recs;
}

// ---------------------------------------------------------------------------
// 存储
// ---------------------------------------------------------------------------
async function putProxy(kv, rec, expiresAt) {
  const key = "p:" + (await sha1Hex(rec.raw));
  const existing = await kv.get(key);
  const now = Date.now();
  if (existing) {
    const old = JSON.parse(existing);
    // 重复上传：刷新（延长）过期时间；仍过期中的不改
    const newExp = expiresAt ?? (old.expires_at ? Math.max(old.expires_at, now + DEFAULT_TTL_MS) : old.expires_at);
    await kv.put(key, JSON.stringify({ ...old, expires_at: newExp ?? old.expires_at, added_at: old.added_at }));
    return "refreshed";
  }
  await kv.put(
    key,
    JSON.stringify({
      raw: rec.raw,
      proto: rec.proto || null,
      host: rec.host || null,
      port: rec.port || null,
      name: rec.name || null,
      added_at: now,
      expires_at: expiresAt ?? null,
    })
  );
  return "added";
}

async function listProxies(kv) {
  const now = Date.now();
  const out = [];
  let cursor;
  do {
    const page = await kv.list({ prefix: "p:", cursor });
    for (const key of page.keys) {
      const raw = await kv.get(key.name);
      if (!raw) continue;
      try {
        const p = JSON.parse(raw);
        if (p.expires_at && p.expires_at < now) {
          await kv.delete(key.name); // lazy 过期
          continue;
        }
        out.push(p);
      } catch {}
    }
    cursor = page.list_complete ? undefined : page.list_cursor;
  } while (cursor);
  return out;
}

async function purgeExpired(kv) {
  const now = Date.now();
  let removed = 0;
  let cursor;
  do {
    const page = await kv.list({ prefix: "p:", cursor });
    for (const key of page.keys) {
      const raw = await kv.get(key.name);
      if (!raw) continue;
      try {
        const p = JSON.parse(raw);
        if (p.expires_at && p.expires_at < now) {
          await kv.delete(key.name);
          removed++;
        }
      } catch {}
    }
    cursor = page.list_complete ? undefined : page.list_cursor;
  } while (cursor);
  return removed;
}

// ---------------------------------------------------------------------------
// Clash YAML 转换（尽力而为：解析失败的跳过）
// ---------------------------------------------------------------------------
export function toClashProxies(records) {
  const out = [];
  let i = 0;
  for (const r of records) {
    i++;
    const name = `PC-${i}-${r.host || r.proto || "node"}`;
    try {
      if (r.proto === "http" || r.proto === "https") {
        out.push({
          name, type: "http", server: r.host.replace(/[\[\]]/g, ""), port: r.port,
          ...(r.user ? { username: r.user } : {}), ...(r.pass ? { password: r.pass } : {}),
        });
      } else if (r.proto === "socks5") {
        out.push({
          name, type: "socks5", server: r.host.replace(/[\[\]]/g, ""), port: r.port,
          ...(r.user ? { username: r.user } : {}), ...(r.pass ? { password: r.pass } : {}),
        });
      } else if (r.proto === "vmess" && r.vmess) {
        out.push({
          name: r.name || name, type: "vmess", server: r.vmess.add,
          port: parseInt(r.vmess.port, 10), uuid: r.vmess.id,
          alterId: 0, cipher: r.vmess.scy || "auto",
          ...(r.vmess.net ? { network: r.vmess.net } : {}),
        });
      } else if (r.proto === "vless" && r.vless) {
        const p = r.vless.params || {};
        out.push({
          name: r.name || name, type: "vless", server: r.host, port: r.port,
          uuid: r.vless.uuid, udp: true,
          ...(p.security === "tls" || p.security === "reality" ? { tls: true, servername: p.sni || r.host } : {}),
          ...(p.type && p.type !== "tcp" ? { network: p.type, "ws-opts": p.path ? { path: p.path } : undefined } : {}),
        });
      } else if (r.proto === "ss" && r.ss) {
        out.push({
          name: r.name || name, type: "ss", server: r.host.replace(/[\[\]]/g, ""), port: r.port,
          cipher: r.ss.method, password: r.ss.password,
        });
      } else if (r.proto === "trojan" && r.trojan) {
        out.push({
          name: r.name || name, type: "trojan", server: r.host, port: r.port,
          password: r.trojan.password, sni: r.host,
        });
      }
    } catch {}
  }
  return out;
}

export function toClashYaml(records) {
  const proxies = toClashProxies(records);
  if (!proxies.length) return "proxies: []\n";
  const lines = ["proxies:"];
  for (const p of proxies) {
    lines.push(`  - name: "${p.name}"`);
    for (const [k, v] of Object.entries(p)) {
      if (k === "name") continue;
      if (v === undefined) continue;
      if (typeof v === "object") {
        lines.push(`    ${k}:`);
        for (const [k2, v2] of Object.entries(v)) lines.push(`      ${k2}: ${JSON.stringify(v2)}`);
      } else if (typeof v === "string") {
        lines.push(`    ${k}: ${JSON.stringify(v)}`);
      } else {
        lines.push(`    ${k}: ${v}`);
      }
    }
  }
  const names = proxies.map((p) => `"${p.name}"`).join(",");
  lines.push("proxy-groups:");
  lines.push("  - name: PROXY");
  lines.push("    type: select");
  lines.push(`    proxies: [${names || '"DIRECT"'}]`);
  lines.push("rules:");
  lines.push("  - MATCH,PROXY");
  return lines.join("\n");
}

export function toUriList(records) {
  return records.map((r) => r.raw).join("\n");
}

export function detectClient(ua) {
  ua = (ua || "").toLowerCase();
  if (ua.includes("clash") || ua.includes("mihomo") || ua.includes("stash") || ua.includes("verge"))
    return "clash";
  return "base64";
}

// ---------------------------------------------------------------------------
// 管理会话
// ---------------------------------------------------------------------------
const sessions = new Map();

function adminAuth(request, env) {
  if (!env.ADMIN_PASSWORD) return jsonResp({ error: "admin disabled" }, 404);
  const cookie = (request.headers.get("cookie") || "").match(/pc_admin=([^;]+)/);
  const token = cookie && cookie[1];
  if (!token || !sessions.has(token) || sessions.get(token) < Date.now())
    return jsonResp({ error: "login required" }, 401);
  return null;
}

/** 上传鉴权：UPLOAD_TOKEN Bearer 或 admin 会话（面板前端提交） */
function uploadAuth(request, env) {
  const auth = request.headers.get("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (env.UPLOAD_TOKEN && token === env.UPLOAD_TOKEN) return null;
  return adminAuth(request, env);
}

// ---------------------------------------------------------------------------
// 主路由
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/healthz") return jsonResp({ ok: true, now: Date.now() });

    // ---- 上传：普通路径（永久）与 expiring 路径（默认 7 天）----
    if ((path === "/api/proxies" || path === "/api/proxies/expiring") && method === "POST") {
      const guard = uploadAuth(request, env);
      if (guard) return guard;

      let expiresAt;
      if (path === "/api/proxies/expiring") {
        const q = resolveExpire(new URL("https://x/?" + url.searchParams.toString()));
        expiresAt = q === null ? Date.now() + DEFAULT_TTL_MS : q;
        if (expiresAt === undefined) return jsonResp({ error: "bad ttl/expire param" }, 400);
      } else {
        expiresAt = resolveExpire(url);
        if (expiresAt === undefined) return jsonResp({ error: "bad ttl/expire param" }, 400);
      }

      const body = await request.text();
      const recs = parseUploadBody(body, request.headers.get("content-type"));
      if (recs === null) return jsonResp({ error: "bad request body" }, 400);
      if (!recs.length) return jsonResp({ error: "no valid proxies" }, 400);

      let added = 0,
        refreshed = 0;
      for (const rec of recs) {
        if ((await putProxy(env.PROXY_KV, rec, expiresAt)) === "added") added++;
        else refreshed++;
      }
      return jsonResp({
        added,
        refreshed,
        total_parsed: recs.length,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        message: expiresAt ? "已入库（到期自动清理）" : "已入库（永久，重复上传续期）",
      });
    }

    // ---- 管理面板 ----
    if (path === "/admin" && method === "GET") {
      if (!env.ADMIN_PASSWORD) return new Response("admin disabled", { status: 404 });
      return new Response(ADMIN_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    if (path === "/api/login" && method === "POST") {
      const { password } = await request.json();
      if (password !== env.ADMIN_PASSWORD) return jsonResp({ error: "wrong password" }, 401);
      const token = crypto.randomUUID();
      sessions.set(token, Date.now() + 12 * 3600 * 1000);
      return jsonResp({ ok: true }, 200, {
        "Set-Cookie": `pc_admin=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`,
      });
    }

    if (path.startsWith("/api/")) {
      const guard = adminAuth(request, env);
      if (guard) return guard;

      // 读取：admin 会话或 UPLOAD_TOKEN（供外部程序拉取全量做出口池）
      if (path === "/api/proxies" && method === "GET") {
        const auth = request.headers.get("authorization") || "";
        const token = auth.replace(/^Bearer\s+/i, "").trim();
        const authorized =
          (env.UPLOAD_TOKEN && token === env.UPLOAD_TOKEN) ||
          !adminAuth(request, env);
        if (!authorized) return jsonResp({ error: "unauthorized" }, 401);
        const proxies = await listProxies(env.PROXY_KV);
        proxies.sort((a, b) => b.added_at - a.added_at);
        return jsonResp({ count: proxies.length, proxies });
      }
      if (path === "/api/proxies/purge" && method === "POST") {
        return jsonResp({ removed: await purgeExpired(env.PROXY_KV) });
      }
      if (path === "/api/subs" && method === "GET") {
        const subs = [];
        let cursor;
        do {
          const page = await env.PROXY_KV.list({ prefix: "sub:", cursor });
          for (const k of page.keys) {
            const raw = await env.PROXY_KV.get(k.name);
            if (raw) subs.push(JSON.parse(raw));
          }
          cursor = page.list_complete ? undefined : page.list_cursor;
        } while (cursor);
        return jsonResp({ subs });
      }
      if (path === "/api/subs" && method === "POST") {
        const { name, expires_days } = await request.json();
        const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
        const sub = {
          id,
          name: (name || "unnamed").slice(0, 60),
          key: crypto.randomUUID().replace(/-/g, ""),
          created_at: Date.now(),
          expires_at: expires_days ? Date.now() + expires_days * 86400 * 1000 : null,
          enabled: true,
        };
        await env.PROXY_KV.put("sub:" + id, JSON.stringify(sub));
        return jsonResp({ sub, url: `${url.origin}/sub/${id}?key=${sub.key}` });
      }
      const subMatch = path.match(/^\/api\/subs\/([a-f0-9]+)\/(update|delete)$/);
      if (subMatch && method === "POST") {
        const kvKey = "sub:" + subMatch[1];
        const raw = await env.PROXY_KV.get(kvKey);
        if (!raw) return jsonResp({ error: "not found" }, 404);
        const sub = JSON.parse(raw);
        if (subMatch[2] === "delete") {
          await env.PROXY_KV.delete(kvKey);
          return jsonResp({ ok: true });
        }
        const { name, expires_days, enabled } = await request.json();
        if (name !== undefined) sub.name = String(name).slice(0, 60);
        if (expires_days !== undefined)
          sub.expires_at = expires_days ? Date.now() + expires_days * 86400 * 1000 : null;
        if (enabled !== undefined) sub.enabled = !!enabled;
        await env.PROXY_KV.put(kvKey, JSON.stringify(sub));
        return jsonResp({ sub });
      }
    }

    // ---- 订阅下发 ----
    const subFetch = path.match(/^\/sub\/([a-f0-9]+)$/);
    if (subFetch && method === "GET") {
      const raw = await env.PROXY_KV.get("sub:" + subFetch[1]);
      if (!raw) return new Response("subscription not found", { status: 404 });
      const sub = JSON.parse(raw);
      if (!sub.enabled) return new Response("subscription disabled", { status: 403 });
      if (sub.key !== url.searchParams.get("key")) return new Response("bad key", { status: 403 });
      if (sub.expires_at && Date.now() > sub.expires_at)
        return new Response("subscription expired", { status: 403 });

      const records = await listProxies(env.PROXY_KV);
      if (!records.length) return new Response("no proxies available", { status: 503 });

      const client = detectClient(request.headers.get("user-agent"));
      let body, ctype;
      if (client === "clash") {
        body = toClashYaml(records);
        ctype = "text/yaml; charset=utf-8";
      } else {
        body = b64encode(toUriList(records));
        ctype = "text/plain; charset=utf-8";
      }
      return new Response(body, {
        headers: {
          "content-type": ctype,
          "subscription-userinfo": `upload=0; download=0; total=0; expire=${Math.floor(
            (sub.expires_at || Date.now() + 86400 * 1000) / 1000
          )}`,
          "profile-update-interval": "12",
        },
      });
    }

    return jsonResp({ error: "not found" }, 404);
  },

  async scheduled(event, env) {
    console.log(`[cron] purged ${await purgeExpired(env.PROXY_KV)} expired proxies`);
  },
};

// ---------------------------------------------------------------------------
// 内嵌管理面板（含前端提交）
// ---------------------------------------------------------------------------
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyCollector</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--tx:#e6edf3;--dim:#8b949e;--green:#238636;--red:#da3633;--blue:#388bfd}
*{box-sizing:border-box;margin:0;padding:0;font-family:ui-monospace,Consolas,monospace}
body{background:var(--bg);color:var(--tx);min-height:100vh;padding:32px 16px}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:20px;margin-bottom:4px}.sub{color:var(--dim);font-size:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:14px}
input,textarea{background:#0d1117;border:1px solid var(--line);color:var(--tx);border-radius:6px;padding:8px 10px;font-size:13px;width:100%}
textarea{min-height:110px;resize:vertical}
button{background:var(--green);border:none;color:#fff;border-radius:6px;padding:8px 14px;font-size:13px;cursor:pointer}
button.ghost{background:transparent;border:1px solid var(--line)}button.red{background:var(--red)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--dim);text-align:left;padding:8px;border-bottom:1px solid var(--line)}td{padding:8px;border-bottom:1px solid var(--line)}
.pill{padding:2px 8px;border-radius:10px;font-size:11px}.pill.on{background:#12351c;color:#3fb950}.pill.off{background:#3d1618;color:#f85149}
.mono{font-size:12px;word-break:break-all}.dim{color:var(--dim);font-size:12px}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--card);border:1px solid var(--line);padding:8px 16px;border-radius:8px;display:none}
</style></head><body><div class="wrap" id="app"></div><div id="toast"></div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(m){const t=$('#toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2400)}
async function api(p,o){const r=await fetch(p,Object.assign({headers:{'content-type':'application/json'}},o||{}));
 if(r.status===401){renderLogin();throw 0}const d=await r.json().catch(()=>({}));if(!r.ok)throw d.error||r.status;return d}
function renderLogin(msg){app.innerHTML='<div class=card style="max-width:360px;margin:60px auto"><h1>ProxyCollector</h1><p class=sub>管理员登录</p><input id=pw type=password placeholder=管理密码><div style=margin-top:12px><button style=width:100% onclick=doLogin()>登录</button></div><div id=e style=color:#f85149;margin-top:8px>'+esc(msg||'')+'</div></div>';$('#pw').focus();$('#pw').onkeydown=e=>{if(e.key=='Enter')doLogin()}}
async function doLogin(){try{await api('/api/login',{method:'POST',body:JSON.stringify({password:$('#pw').value})});renderPanel();load()}catch(e){if(e!==0)renderLogin('登录失败')}}
function renderPanel(){app.innerHTML='<h1>ProxyCollector <button class=ghost style=float:right onclick="location.reload()">刷新</button></h1><p class=sub>代理收集 · 订阅分发 · 过期自动清理</p>'
 +'<div class=card><b>前端提交代理</b><div class=dim style=margin:6px 0>每行一条，支持 vmess:// vless:// ss:// trojan:// socks5:// http:// / host:port:user:pass / host:port；下面选择过期方式</div>'
 +'<textarea id=pin placeholder=proxy lines...></textarea><div class=row style=margin-top:8px>'
 +'<select id=pexp style="background:#0d1117;border:1px solid var(--line);color:var(--tx);border-radius:6px;padding:8px"><option value="">永久</option><option value="expiring">7 天（ProxyScrape 试用）</option><option value="custom">自定义…</option></select>'
 +'<input id=pexpv placeholder="如 48h / 7d / 2026-10-01" style="flex:1;display:none">'
 +'<button onclick=submitProxies()>提交</button></div><div id=pmsg class=dim style=margin-top:8px></div></div>'
 +'<div class=card><b>创建订阅</b><div class=row style=margin-top:10px><input id=sname placeholder=订阅名 style=flex:2><input id=sdays type=number placeholder=有效期(天,空=永久) style=flex:1><button onclick=createSub()>创建</button></div><div class=dim style=margin-top:6px>订阅按 User-Agent 自动适配 Clash YAML / base64 URI（v2rayN、sing-box 等）</div></div>'
 +'<div class=card><div class=row><b>订阅列表</b><button class=ghost style=margin-left:auto onclick=load()>刷新</button></div><table style=margin-top:10px><thead><tr><th>名称</th><th>链接</th><th>有效期</th><th>状态</th><th>操作</th></tr></thead><tbody id=subs></tbody></table></div>'
 +'<div class=card><div class=row><b>代理池</b><span class=dim style=margin-left:auto id=stat></span><button class=red onclick=purge()>清理过期</button></div><div id=proxies class=mono style=margin-top:10px;max-height:300px;overflow:auto></div></div>'}
async function load(){try{const[st,pr]=await Promise.all([api('/api/stats'),api('/api/proxies')]);
 $('#stat').textContent='代理 '+st.proxy_count+' 条'+(st.oldest?' · 最早 '+st.oldest.slice(0,10):'');
 $('#subs').innerHTML=pr.subs.map(s=>'<tr><td>'+esc(s.name)+'</td>'
  +'<td class=mono><a href="/sub/'+s.id+'?key='+esc(s.key)+'" target=_blank style=color:var(--blue)>/sub/'+esc(s.id.slice(0,8))+'…</a> '
  +'<button class=ghost style="padding:2px 6px;font-size:10px" onclick="copySub(\\\''+esc(s.id)+'\\\',\\\''+esc(s.key)+'\\\')">复制</button></td>'
  +'<td class=dim>'+(s.expires_at?esc(new Date(s.expires_at).toISOString().slice(0,10)):'永久')+'</td>'
  +'<td><span class="pill '+(s.enabled?'on':'off')+'">'+(s.enabled?'启用':'禁用')+'</span></td>'
  +'<td><button class=ghost onclick=toggle(\\\''+esc(s.id)+'\\\','+(!s.enabled)+')>'+(s.enabled?'禁用':'启用')+'</button> '
  +'<button class=red onclick=del(\\\''+esc(s.id)+'\\\')>删除</button></td></tr>').join('')
  ||'<tr><td colspan=5 class=dim>暂无订阅</td></tr>';
 $('#proxies').innerHTML=pr.proxies.slice(0,60).map(p=>'<div>'+esc(p.raw.slice(0,90))+(p.expires_at?' <span class=dim>[至 '+new Date(p.expires_at).toISOString().slice(0,10)+']</span>':'')+'</div>').join('')
  +'<div class=dim>（最近 60 条，共 '+pr.count+' 条；无标记 = 永久）</div>'}catch(e){if(e!==0)toast('加载失败: '+e)}}
function copySub(id,key){navigator.clipboard.writeText(location.origin+'/sub/'+id+'?key='+key).then(()=>toast('订阅链接已复制'),()=>toast('复制失败，请手动复制'))}
async function submitProxies(){
 const mode=$('#pexp').value, custom=$('#pexpv').value.trim();
 let qs='';
 if(mode==='expiring')qs='';                       // /expiring 默认 7 天
 else if(mode==='custom'&&custom)qs='?ttl='+encodeURIComponent(custom);
 else if(mode==='custom'){$('#pmsg').textContent='请填写自定义时间';return}
 try{
  const r=await fetch('/api/proxies'+(mode==='expiring'?'/expiring':'')+qs,{method:'POST',
   headers:{'content-type':'text/plain'},body:$('#pin').value});
  const d=await r.json().catch(()=>({}));
  if(!r.ok){$('#pmsg').textContent='失败: '+(d.error||r.status);return}
  $('#pmsg').textContent='已提交: 新增 '+d.added+'，续期 '+d.refreshed+(d.expires_at?'，过期 '+d.expires_at.slice(0,10):'（永久）');
  $('#pin').value='';load()
 }catch(e){$('#pmsg').textContent='提交异常: '+e}}
$('#pexp').addEventListener('change',()=>{$('#pexpv').style.display=$('#pexp').value==='custom'?'block':'none'});
async function createSub(){try{const d=await api('/api/subs',{method:'POST',body:JSON.stringify({name:$('#sname').value,expires_days:$('#sdays').value?Number($('#sdays').value):null})});
 navigator.clipboard.writeText(d.url).catch(()=>{});toast('订阅已创建，链接已复制');load()}catch(e){toast('失败: '+e)}}
async function toggle(id,en){try{await api('/api/subs/'+id+'/update',{method:'POST',body:JSON.stringify({enabled:en})});load()}catch(e){toast('失败: '+e)}}
async function del(id){if(!confirm('删除该订阅？'))return;try{await api('/api/subs/'+id+'/delete',{method:'POST'});load()}catch(e){toast('失败: '+e)}}
async function purge(){try{const d=await api('/api/proxies/purge',{method:'POST'});toast('已清理 '+d.removed+' 条过期代理');load()}catch(e){toast('失败: '+e)}}
(async()=>{try{await api('/api/stats');renderPanel();load()}catch(e){if(e!==0)renderLogin()}})();
</script></body></html>`;
