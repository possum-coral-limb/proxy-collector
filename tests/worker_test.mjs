// worker.js 端到端测试：内存 KV stub + 直接调用 fetch handler。
// worker.js 用了 ESM export 但仓库无 package.json —— 复制为 .mjs 后动态 import。
import { readFileSync, copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), "pc-test-"));
copyFileSync(join(repoRoot, "worker.js"), join(tmp, "worker.mjs"));
const mod = await import(pathToFileURL(join(tmp, "worker.mjs")).href);
const {
  parseProxyLine, parseUploadBody, parseClashYaml, parseSingBoxYaml,
  toClashYaml, default: worker,
} = mod;

// ---- KV stub（无分页，一次 list 返回全部） ----
function kvStub() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, String(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix } = {}) {
      const keys = [...m.keys()].filter((k) => k.startsWith(prefix || "")).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
    _m: m,
  };
}

const env = { PROXY_KV: kvStub(), UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); passed++; console.log("PASS", name); }
  catch (e) { failed++; console.error("FAIL", name, "\n     ", String(e.message).split("\n")[0]); }
}

// ---- 1. 新 URI 解析 ----
await t("parseProxyLine tuic://", () => {
  const r = parseProxyLine("tuic://uuid-abcd:mypass%21@1.2.3.4:443?sni=example.com&congestion_control=bbr&alpn=h3#TUIC%E8%8A%82%E7%82%B9");
  assert.equal(r.proto, "tuic");
  assert.equal(r.host, "1.2.3.4");
  assert.equal(r.port, 443);
  assert.equal(r.tuic.uuid, "uuid-abcd");
  assert.equal(r.tuic.password, "mypass!");
  assert.equal(r.tuic.params.sni, "example.com");
  assert.equal(r.tuic.params.congestion_control, "bbr");
  assert.equal(r.name, "TUIC节点");
});
await t("parseProxyLine hy2:// 与 hysteria2://", () => {
  const a = parseProxyLine("hy2://pass%40word@5.6.7.8:8443/?insecure=1&obfs=salamander&obfs-password=obfspw&sni=h.com#hy2name");
  assert.equal(a.proto, "hysteria2");
  assert.equal(a.hy2.password, "pass@word");
  assert.equal(a.hy2.params["obfs-password"], "obfspw");
  assert.equal(a.hy2.params.insecure, "1");
  const b = parseProxyLine("hysteria2://pw@5.6.7.8:8443#x");
  assert.equal(b.proto, "hysteria2");
});
await t("parseProxyLine anytls://", () => {
  const r = parseProxyLine("anytls://pw9@9.9.9.9:443?sni=a.com&insecure=0#at");
  assert.equal(r.proto, "anytls");
  assert.equal(r.anytls.password, "pw9");
  assert.equal(r.anytls.params.sni, "a.com");
  assert.equal(r.port, 443);
});

// ---- 2. Clash YAML 上传 ----
const CLASH_YAML = `port: 7890
proxies:
  - name: "ss1"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: "ss#pass"
  - {name: tr1, type: trojan, server: 2.2.2.2, port: 443, password: trpass, sni: tr.example.com}
  - name: vm1
    type: vmess
    server: 3.3.3.3
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: ws.example.com
  - name: tuic1
    type: tuic
    server: 4.4.4.4
    port: 8443
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    password: tuicpw
    sni: t.example.com
    congestion-controller: bbr
    alpn: [h3]
  - name: hy21
    type: hysteria2
    server: 5.5.5.5
    port: 36712
    password: hy2pw
    sni: h.example.com
    obfs: salamander
    obfs-password: obfspw
  - name: at1
    type: anytls
    server: 6.6.6.6
    port: 8443
    password: atpw
    sni: a.example.com
proxy-groups:
  - name: PROXY
    type: select
    proxies: [ss1, tr1]
rules:
  - MATCH,PROXY
`;
await t("parseClashYaml 6 条全类型", () => {
  const recs = parseClashYaml(CLASH_YAML);
  assert.equal(recs.length, 6);
  const by = Object.fromEntries(recs.map((r) => [r.proto === "hysteria2" ? "hy21" : r.name, r]));
  assert.ok(recs.every((r) => ["tuic", "hysteria2", "anytls", "vmess", "ss", "trojan"].includes(r.proto)));
  assert.ok(by.ss1.raw.startsWith("ss://"));
  assert.equal(by.tr1.trojan.password, "trpass");
  assert.equal(by.tr1.trojan.params.sni, "tr.example.com");
  assert.equal(by.vm1.vmess.add, "3.3.3.3");
  assert.equal(by.tuic1.tuic.uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  assert.equal(by.hy21.hy2.params["obfs-password"], "obfspw");
  assert.equal(by.at1.anytls.password, "atpw");
});
await t("parseUploadBody 检测 Clash YAML", () => {
  const recs = parseUploadBody(CLASH_YAML, "text/yaml");
  assert.equal(recs.length, 6);
});

// ---- 3. sing-box YAML 上传 ----
const SB_YAML = `log:
  level: info
outbounds:
  - type: shadowsocks
    tag: sb-ss
    server: 7.7.7.7
    server_port: 8388
    method: aes-128-gcm
    password: sbssp
  - type: tuic
    tag: sb-tuic
    server: 8.8.8.8
    server_port: 8443
    uuid: 11111111-2222-3333-4444-555555555555
    password: sbtp
    congestion_control: bbr
    tls: {enabled: true, server_name: sb.example.com, alpn: [h3]}
  - type: hysteria2
    tag: sb-hy2
    server: 9.9.9.9
    server_port: 36712
    password: sbhp
    obfs:
      type: salamander
      password: sbop
    tls: {enabled: true, server_name: sbh.example.com}
  - type: anytls
    tag: sb-at
    server: 10.0.0.1
    server_port: 8443
    password: sbap
    tls: {enabled: true, server_name: sba.example.com}
  - type: direct
    tag: direct
  - type: vmess
    tag: sb-vm
    server: 10.0.0.2
    server_port: 443
    uuid: 99999999-8888-7777-6666-555555555555
    security: auto
    tls: {enabled: true, server_name: svm.example.com}
    transport:
      type: ws
      path: /sb
      headers:
        Host: sbv.example.com
  - type: trojan
    tag: sb-tr
    server: 10.0.0.3
    server_port: 443
    password: sbtrp
    tls: {enabled: true, server_name: sbt.example.com}
`;
await t("parseSingBoxYaml 6 条（7 条目，direct 跳过）", () => {
  const recs = parseSingBoxYaml(SB_YAML);
  assert.equal(recs.length, 6);
  const by = Object.fromEntries(recs.map((r) => [r.name, r]));
  assert.equal(by["sb-tuic"].proto, "tuic");
  assert.equal(by["sb-hy2"].proto, "hysteria2");
  assert.equal(by["sb-hy2"].hy2.params["obfs-password"], "sbop");
  assert.equal(by["sb-at"].proto, "anytls");
  assert.equal(by["sb-vm"].proto, "vmess");
  assert.equal(by["sb-tr"].proto, "trojan");
  assert.equal(by["sb-ss"].ss.method, "aes-128-gcm");
});
await t("parseUploadBody 检测 sing-box YAML", () => {
  const recs = parseUploadBody(SB_YAML, "");
  assert.equal(recs.length, 6);
});

// ---- 4. Clash 订阅输出：存储形态记录（无结构化字段）经 raw 重析 ----
await t("toClashYaml 覆盖全部协议（含存储形态记录）", () => {
  const recs = [
    { raw: "tuic://uuid-abcd:mypass@1.2.3.4:443?sni=example.com&congestion_control=bbr&alpn=h3#TUIC1", proto: "tuic", host: "1.2.3.4", port: 443, name: "TUIC1" },
    { raw: "hy2://pw@5.5.5.5:36712?obfs=salamander&obfs-password=obfspw#HY2X", proto: "hysteria2", host: "5.5.5.5", port: 36712, name: "HY2X" },
    { raw: "anytls://apw@6.6.6.6:8443?sni=a.example.com#ATX", proto: "anytls", host: "6.6.6.6", port: 8443, name: "ATX" },
    { raw: "ss://" + Buffer.from("aes-128-gcm:pw1").toString("base64") + "@7.7.7.7:8388#SSX", proto: "ss", host: "7.7.7.7", port: 8388, name: "SSX" },
  ];
  const yaml = toClashYaml(recs);
  assert.ok(yaml.includes('type: "tuic"'));
  assert.ok(yaml.includes('type: "hysteria2"'));
  assert.ok(yaml.includes('type: "anytls"'));
  assert.ok(yaml.includes('type: "ss"'));
  assert.ok(yaml.includes('congestion-controller: "bbr"'));
  assert.ok(yaml.includes('obfs-password: "obfspw"'));
});

// ---- 5. 端到端：上传 → 订阅下发 ----
await t("E2E 上传 Clash YAML → added=6", async () => {
  const req = new Request("https://w.test/api/proxies", {
    method: "POST",
    body: CLASH_YAML,
    headers: { "content-type": "text/yaml", authorization: "Bearer tok" },
  });
  const res = await worker.fetch(req, env);
  const j = await res.json();
  assert.equal(res.status, 200);
  assert.equal(j.added, 6);
});
await t("E2E 重复上传 → refreshed=6", async () => {
  const req = new Request("https://w.test/api/proxies", {
    method: "POST", body: CLASH_YAML,
    headers: { authorization: "Bearer tok" },
  });
  const j = await (await worker.fetch(req, env)).json();
  assert.equal(j.added, 0);
  assert.equal(j.refreshed, 6);
});
let subUrl = "";
await t("E2E 登录 + 建订阅", async () => {
  const login = await worker.fetch(new Request("https://w.test/api/login", {
    method: "POST", body: JSON.stringify({ password: "pw" }),
  }), env);
  const cookie = login.headers.get("set-cookie").match(/pc_admin=[^;]+/)[0];
  const res = await worker.fetch(new Request("https://w.test/api/subs", {
    method: "POST", body: JSON.stringify({ name: "e2e" }),
    headers: { cookie },
  }), env);
  const j = await res.json();
  assert.ok(j.url.includes("/sub/"));
  subUrl = j.url;
});
await t("E2E Clash UA 订阅 → YAML 含新协议", async () => {
  const res = await worker.fetch(new Request(subUrl, {
    headers: { "user-agent": "clash-verge/2.0" },
  }), env);
  const body = await res.text();
  assert.equal(res.status, 200);
  for (const s of ['type: "tuic"', 'type: "hysteria2"', 'type: "anytls"', 'type: "vmess"', 'type: "ss"', 'type: "trojan"'])
    assert.ok(body.includes(s), `缺少 ${s}`);
});
await t("E2E 通用 UA 订阅 → base64 直出新 URI", async () => {
  const res = await worker.fetch(new Request(subUrl, {
    headers: { "user-agent": "curl/8.0" },
  }), env);
  const body = Buffer.from(await res.text(), "base64").toString("utf8");
  for (const s of ["tuic://", "hy2://", "anytls://", "vmess://", "ss://", "trojan://"])
    assert.ok(body.includes(s), `缺少 ${s}`);
});
await t("E2E 上传 sing-box YAML → added=6", async () => {
  const req = new Request("https://w.test/api/proxies", {
    method: "POST", body: SB_YAML,
    headers: { authorization: "Bearer tok" },
  });
  const j = await (await worker.fetch(req, env)).json();
  assert.equal(j.added, 6);
});
await t("E2E 混合 URI 行上传（新协议 + 老格式共存）", async () => {
  const body = "tuic://u1:p1@11.11.11.11:443?sni=x.com#mix1\nhy2://p2@12.12.12.12:8443#mix2\nanytls://p3@13.13.13.13:443#mix3\n1.2.3.4:8080:user:pass";
  const req = new Request("https://w.test/api/proxies", {
    method: "POST", body,
    headers: { authorization: "Bearer tok" },
  });
  const j = await (await worker.fetch(req, env)).json();
  assert.equal(j.added, 4);
});

// ---- 6. 单条 KV 存储：往返次数与条数无关 ----
// 历史：逐条存储时订阅下发要 list + 逐条 get（200 条 = 201 次往返，实测 ~1 分钟）；
// 现在全部代理存单条 blob，读 = 1 次 get，一批上传 = 1 读 + 1 写。
function countingKv(latencyMs = 0) {
  const store = new Map();
  const counts = { get: 0, put: 0, list: 0, delete: 0 };
  return {
    store, counts,
    async get(k) { counts.get++; if (latencyMs) await new Promise((r) => setTimeout(r, latencyMs)); return store.has(k) ? store.get(k) : null; },
    async put(k, v) { counts.put++; if (latencyMs) await new Promise((r) => setTimeout(r, latencyMs)); store.set(k, String(v)); },
    async delete(k) { counts.delete++; store.delete(k); },
    async list({ prefix } = {}) {
      counts.list++;
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix || "")).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
  };
}

await t("上传一批 = 2 读 + 1 写（含写后完整性校验）", async () => {
  const kv = countingKv();
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const post = (body) => worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body, headers: { authorization: "Bearer tok" },
  }), localEnv);
  // 第一次上传：全新 KV 会做一次性旧键迁移探测（list 1 次），写入 blob
  const body1 = Array.from({ length: 200 }, (_, i) => `1.2.3.${i % 250}:8080:user${i}:pass${i}`).join("\n");
  const j1 = await (await post(body1)).json();
  assert.equal(j1.added, 200, "200 条应全部入库");
  assert.equal(kv.counts.get, 2, `上传应 2 次读（合并 + 写后校验，实测 ${kv.counts.get}）`);
  assert.equal(kv.counts.put, 1, `上传只应 1 次写（实测 ${kv.counts.put}）`);
  assert.ok(kv.counts.list <= 1, `首次最多 1 次迁移探测（实测 ${kv.counts.list}）`);
  // 第二次上传：稳态 —— 不再有任何 list
  kv.counts.get = kv.counts.put = kv.counts.list = 0;
  const body2 = Array.from({ length: 200 }, (_, i) => `10.9.${i % 250}.${(i + 7) % 250}:8080`).join("\n");
  const j2 = await (await post(body2)).json();
  assert.equal(j2.added, 200);
  assert.equal(kv.counts.get, 2, `稳态上传应 2 次读（实测 ${kv.counts.get}）`);
  assert.equal(kv.counts.put, 1, `稳态上传只应 1 次写（实测 ${kv.counts.put}）`);
  assert.equal(kv.counts.list, 0, `稳态上传不应触发 list（实测 ${kv.counts.list}）`);
});

await t("并发上传竞态：写后校验缩小丢失窗口，后续顺序重传自愈", async () => {  const kv = countingKv();
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const post = (body) => worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body, headers: { authorization: "Bearer tok" },
  }), localEnv);
  const bodyA = Array.from({ length: 100 }, (_, i) => `10.1.0.${i}:1000`).join("\n");
  const bodyB = Array.from({ length: 100 }, (_, i) => `10.2.0.${i}:2000`).join("\n");
  // KV 无 CAS，并发读-改-写的覆盖窗口无法在 worker 内彻底消除（写入方应顺序上传）。
  // 保证的是：哪怕并发批次互相覆盖，之后任何一次顺序重传都能恢复全量。
  await Promise.all([post(bodyA), post(bodyB)]);
  await post(bodyA);
  await post(bodyB);
  const res = await worker.fetch(new Request("https://w.test/api/proxies", {
    headers: { authorization: "Bearer tok" },
  }), localEnv);
  const j = await res.json();
  assert.equal(j.count, 200, "顺序重传后两条都应完整（自愈）");
});

await t("订阅下发 = 1 次读（200 条，不再逐条 get）", async () => {
  const kv = countingKv(3);   // 每次 3ms 往返，串行 get 会立刻暴露
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const lines = Array.from({ length: 200 }, (_, i) => `10.0.${Math.floor(i / 250) % 250}.${i % 250}:8080`).join("\n");
  await worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body: lines, headers: { authorization: "Bearer tok" },
  }), localEnv);
  kv.counts.get = 0;
  // 建订阅 + 拉取
  const login = await worker.fetch(new Request("https://w.test/api/login", {
    method: "POST", body: JSON.stringify({ password: "pw" }),
  }), localEnv);
  const cookie = login.headers.get("set-cookie").match(/pc_admin=[^;]+/)[0];
  const sub = await (await worker.fetch(new Request("https://w.test/api/subs", {
    method: "POST", body: JSON.stringify({ name: "perf" }), headers: { cookie },
  }), localEnv)).json();
  const res = await worker.fetch(new Request(sub.url, { headers: { "user-agent": "curl/8.0" } }), localEnv);
  assert.equal(res.status, 200);
  const bodyText = Buffer.from(await res.text(), "base64").toString("utf8");
  assert.equal(bodyText.split("\n").filter(Boolean).length, 200);
  // 2 次 = sub:<id> 记录 1 次 + 代理 blob 1 次（旧方案是 1 + 200 次逐条 get）
  assert.equal(kv.counts.get, 2, `订阅下发应只 2 次 KV get（实测 ${kv.counts.get}）`);
});

async function adminCookie(worker, env) {
  const login = await worker.fetch(new Request("https://w.test/api/login", {
    method: "POST", body: JSON.stringify({ password: env.ADMIN_PASSWORD }),
  }), env);
  return login.headers.get("set-cookie").match(/pc_admin=[^;]+/)[0];
}

await t("万条订阅 base64 不爆栈（b64encode 分块）", async () => {
  const kv = countingKv();
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const lines = Array.from({ length: 15000 }, (_, i) =>
    `10.${Math.floor(i / 65536) % 250}.${Math.floor(i / 256) % 250}.${i % 250}:${1000 + (i % 60000)}`).join("\n");
  await worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body: lines, headers: { authorization: "Bearer tok" },
  }), localEnv);
  const login = await worker.fetch(new Request("https://w.test/api/login", {
    method: "POST", body: JSON.stringify({ password: "pw" }),
  }), localEnv);
  const cookie = login.headers.get("set-cookie").match(/pc_admin=[^;]+/)[0];
  const sub = await (await worker.fetch(new Request("https://w.test/api/subs", {
    method: "POST", body: JSON.stringify({ name: "big" }), headers: { cookie },
  }), localEnv)).json();
  const res = await worker.fetch(new Request(sub.url, { headers: { "user-agent": "curl/8.0" } }), localEnv);
  assert.equal(res.status, 200, "万条订阅应 200（旧 b64encode 会栈溢出 500）");
  const bodyText = Buffer.from(await res.text(), "base64").toString("utf8");
  assert.equal(bodyText.split("\n").filter(Boolean).length, 15000, "解码后应为 15000 行");
});

await t("旧格式 p:<sha1> 键自动迁移进 blob 并删除", async () => {
  const kv = countingKv();
  const crypto = await import("node:crypto");
  const sha1 = (s) => crypto.createHash("sha1").update(s).digest("hex");
  const legacy = [
    { raw: "vmess://legacy1", proto: "vmess", host: "1.1.1.1", port: 443, added_at: 111, expires_at: null },
    { raw: "ss://legacy2", proto: "ss", host: "2.2.2.2", port: 8388, added_at: 222, expires_at: null },
  ];
  for (const p of legacy) kv.store.set("p:" + sha1(p.raw), JSON.stringify(p));
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const cookie = await adminCookie(worker, localEnv);
  const res = await worker.fetch(new Request("https://w.test/api/proxies", {
    headers: { cookie },
  }), localEnv);
  const j = await res.json();
  assert.equal(j.count, 2, "旧键数据应迁移可见");
  assert.ok(kv.store.has("store:proxies"), "应写入新 blob");
  assert.equal([...kv.store.keys()].filter((k) => k.startsWith("p:")).length, 0, "旧键应被删除");
});

await t("重复上传续期 + 永久/过期语义不变", async () => {
  const kv = countingKv();
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const post = (body, path = "/api/proxies") => worker.fetch(new Request("https://w.test" + path, {
    method: "POST", body, headers: { authorization: "Bearer tok" },
  }), localEnv);
  assert.equal((await (await post("1.2.3.4:8080")).json()).added, 1);
  assert.equal((await (await post("1.2.3.4:8080")).json()).refreshed, 1, "重复上传应续期");
  // 7 天过期路径 + 过期后从读取中消失（懒清理）
  await post("5.6.7.8:9999", "/api/proxies/expiring?ttl=1s");
  await new Promise((r) => setTimeout(r, 1100));
  const cookie = await adminCookie(worker, localEnv);
  const list = await (await worker.fetch(new Request("https://w.test/api/proxies", {
    headers: { cookie },
  }), localEnv)).json();
  const raws = list.proxies.map((p) => p.raw);
  assert.ok(raws.includes("1.2.3.4:8080"), "永久代理仍在");
  assert.ok(!raws.includes("5.6.7.8:9999"), "过期代理应被懒清理");
});

await t("GET /api/proxies 仅 Bearer UPLOAD_TOKEN（无 admin 会话）可用", async () => {
  const kv = countingKv();
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  await worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body: "1.2.3.4:8080", headers: { authorization: "Bearer tok" },
  }), localEnv);
  const res = await worker.fetch(new Request("https://w.test/api/proxies", {
    headers: { authorization: "Bearer tok" },
  }), localEnv);
  assert.equal(res.status, 200, "Bearer 拉取全量应放行（外部出口池用途）");
  const j = await res.json();
  assert.equal(j.count, 1, "应返回已上传的 1 条");
  // 无凭据仍应 401
  const res2 = await worker.fetch(new Request("https://w.test/api/proxies"), localEnv);
  assert.equal(res2.status, 401, "无凭据应拒绝");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
