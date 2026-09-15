// 面板启动回归测试：提取 ADMIN_HTML 里的 <script>，在忠实 DOM shim 中执行。
// 背景：曾因脚本顶层访问动态创建的 #pexp 元素抛 TypeError，整个面板纯黑一片。
// shim 行为：静态 DOM 只有 #app/#toast；innerHTML 赋值时才注册新 id；
// 查询不存在的选择器返回 null —— 与真浏览器一致。
import { readFileSync, copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), "pc-panel-"));
copyFileSync(join(repoRoot, "worker.js"), join(tmp, "worker.mjs"));
const src = readFileSync(join(tmp, "worker.mjs"), "utf8");

const m = src.match(/const ADMIN_HTML = `([\s\S]*?)`;\s*$/m);
if (!m) { console.error("FAIL: 未找到 ADMIN_HTML"); process.exit(1); }
const script = m[1].match(/<script>([\s\S]*?)<\/script>/)[1];

function makeEl() {
  return {
    _html: "", textContent: "", style: {}, value: "", _l: null, onkeydown: null,
    focus() {}, addEventListener(t, fn) { (this._l ??= {})[t] = fn; },
  };
}
const byId = {};
for (const id of ["#app", "#toast"]) byId[id] = makeEl();  // 静态 HTML 里只有这两个
function registerIds(html) {
  for (const mm of html.matchAll(/id=([\w-]+)/g)) {
    const k = "#" + mm[1];
    if (!byId[k]) byId[k] = makeEl();
  }
}
const appEl = byId["#app"];
Object.defineProperty(appEl, "innerHTML", {
  set(v) { registerIds(v); this._html = v; }, get() { return this._html; },
});
globalThis.document = { querySelector: (s) => byId[s] ?? null };
globalThis.app = appEl;
globalThis.location = { origin: "http://x" };
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async () => {} } } });
globalThis.fetch = async () => ({ status: 401, ok: false, json: async () => ({}) });
globalThis.confirm = async () => true;

let failed = 0;
try {
  (0, eval)(script);
} catch (e) {
  console.error("FAIL: 脚本顶层抛异常（= 面板纯黑根因）:", e.constructor.name, e.message);
  process.exit(1);
}
await new Promise((r) => setTimeout(r, 50));

if (!appEl.innerHTML.includes("管理员登录")) {
  console.error("FAIL: 未渲染登录框, innerHTML =", appEl.innerHTML.slice(0, 80));
  process.exit(1);
}
console.log("PASS: 启动探测 401 → renderLogin 正常渲染");

globalThis.renderPanel();  // 间接 eval（非严格模式）下函数声明挂到全局
const pexp = byId["#pexp"];
if (!pexp || !pexp._l || !pexp._l.change) {
  console.error("FAIL: #pexp 未挂 change 监听");
  failed++;
} else {
  pexp._l.change();
  if (byId["#pexpv"].style.display !== "none") { console.error("FAIL: 自定义输入框未隐藏"); failed++; }
  else console.log("PASS: renderPanel 内挂载 #pexp change 监听正常");
}
process.exit(failed ? 1 : 0);
