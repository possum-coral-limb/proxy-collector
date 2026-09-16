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

// ---- 6. 上传吞吐：并发写 KV ----
await t("上传并发（不再逐条串行）", async () => {
  // 计数 + 记录最大并发：串行实现的最大并发恒为 1（历史：~50 条/分钟）
  let inFlight = 0, maxInFlight = 0;
  const kv = {
    store: new Map(),
    async get(k) { return this.store.has(k) ? this.store.get(k) : null; },
    async put(k, v) {
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));   // 模拟 KV 往返
      this.store.set(k, String(v)); inFlight--;
    },
    async delete(k) { this.store.delete(k); },
    async list({ prefix } = {}) {
      const keys = [...this.store.keys()].filter((k) => k.startsWith(prefix || "")).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
  };
  const localEnv = { PROXY_KV: kv, UPLOAD_TOKEN: "tok", ADMIN_PASSWORD: "pw" };
  const body = Array.from({ length: 60 }, (_, i) => `1.2.3.${i % 250}:8080:user${i}:pass${i}`).join("\n");
  const res = await worker.fetch(new Request("https://w.test/api/proxies", {
    method: "POST", body, headers: { authorization: "Bearer tok" },
  }), localEnv);
  const j = await res.json();
  assert.equal(j.added, 60, "60 条应全部入库");
  assert.ok(maxInFlight > 1, `写入应并发（实测最大并发 ${maxInFlight}）`);
  assert.ok(maxInFlight <= 25, `并发不得超过 PUT_CONCURRENCY（实测 ${maxInFlight}）`);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
