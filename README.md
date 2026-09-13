# ProxyCollector —— 代理收集与订阅分发（Cloudflare Worker）

单文件 Worker：收集各类代理，按客户端类型自动适配订阅格式下发，支持每条代理独立过期时间（7 天试用代理专用路径 + 自由 TTL），内置管理面板与前端提交。

支持协议：`http` / `https` / `socks5` / `vmess://` / `vless://` / `ss://` / `trojan://` / sing-box JSON outbounds

## 部署（5 分钟）

```bash
npx wrangler login
npx wrangler kv namespace create PROXY_KV
# 把输出的 id 填进 wrangler.toml 的 [[kv_namespaces]] id
npx wrangler secret put UPLOAD_TOKEN      # 自定义随机 token（上传认证）
npx wrangler secret put ADMIN_PASSWORD    # 自定义管理面板密码
npx wrangler deploy
```

## 上传 API

```
POST /api/proxies            永久存储（默认）
POST /api/proxies/expiring   默认 7 天过期（ProxyScrape 试用代理等短期资源专用）
POST /api/proxies?ttl=48h    相对 TTL（s/m/h/d）
POST /api/proxies?expire=2026-10-01T00:00:00Z   绝对过期时间
POST /api/proxies?expire_days=7              按天数

Authorization: Bearer <UPLOAD_TOKEN>
Content-Type: text/plain（每行一条）或 application/json（{"proxies":[...]} / sing-box {"outbounds":[...]}）
```

支持的行格式：

```
http://user:pass@host:port        socks5://user:pass@host:port
vmess://BASE64JSON                vless://uuid@host:port?params#name
ss://BASE64(method:pass@host:port)#name     trojan://pass@host:port#name
host:port:user:pass               user:pass@host:port
host:port
{"outbounds":[...]}               （sing-box，Content-Type: application/json）
```

响应：`{"added": 新增数, "refreshed": 续期数, "expires_at": "..."}`
重复上传同一行会刷新/延长其过期时间（活跃代理不被清理）。

## 订阅下发

`GET /sub/<id>?key=<key>`，按 User-Agent 自动适配：

| 客户端 | 格式 |
|---|---|
| Clash / Mihomo / Stash / Verge | 完整 Clash YAML（http/socks5/vmess/vless/ss/trojan 混排） |
| v2rayN / v2rayNG / sing-box / Shadowrocket 及未知 | base64 编码的原始 URI 列表（无损直出） |

响应头：`subscription-userinfo` + `profile-update-interval: 12`（客户端 12h 自动更新）。

## 管理面板 `/admin`

- **前端提交代理**：文本域粘贴 + 过期方式选择（永久 / 7 天 / 自定义 TTL 或日期）
- 创建订阅：名称 + 有效期（空 = 永久），订阅链接一键复制
- 订阅管理：启用/禁用、改有效期、删除
- 代理池：数量统计、明细查看（含各自过期时间）、手动清理过期

## 过期机制

- 每条代理独立 `expires_at`（null = 永久）
- 读取时懒过滤 + Cron 每日硬清理（UTC 19:00 = 北京 03:00）
- 过期时间可被重新上传延长

## 接入示例（任意来源的代理自动上传）

任何脚本/程序拉取到代理后，都可以推到本服务统一管理与分发：

```bash
curl -X POST "https://<worker>/api/proxies/expiring?ttl=7d" \
  -H "Authorization: Bearer <UPLOAD_TOKEN>" \
  --data-binary @proxies.txt
```

`/expiring` 路径 = 7 天自动过期（适合短期试用资源）；`?ttl=48h`、`?expire=2026-10-01` 等参数可自由设置删除时间。
