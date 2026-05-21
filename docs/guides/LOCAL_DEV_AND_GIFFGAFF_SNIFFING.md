# 本地开发与 Giffgaff `client_secret` 抓包攻略

> 从零开始把 eSIM-Tools 在本地跑起来，并通过抓包 Giffgaff 官方 Android App 获取 OAuth `client_secret`，让本地完整联调 Giffgaff API。
>
> 适用：macOS + Android。Windows / Linux 思路相同，命令需自行替换。

---

## 1. 这份文档解决什么问题

直接 `npm start` 会撞到 4 个坑：

| 阶段 | 报错 | 根因 |
|------|------|------|
| 启动 | `Logger.log is not a function` | [server.js](../../server.js) 误 `require` 了前端 ES6 module 版的 logger（已修复，提交在本仓库） |
| 启动 | `❌ ACCESS_KEY 未配置` | 没有 `.env` |
| OAuth 回调 | `POST /bff/giffgaff-token-exchange 404` | [server.js](../../server.js) 只挂了 `/.netlify/functions/*`，没挂 `/bff/*`（已修复） |
| Token 交换 | `GIFFGAFF_CLIENT_SECRET 未配置` | 该 secret 是 Giffgaff 官方 App 的内置凭据，**不在公开渠道**，必须自己抓包 |

前 3 个坑在本仓库已修复。这份文档主要展开第 4 个：**怎么正规、不破坏手机的情况下抓到 `GIFFGAFF_CLIENT_SECRET`**。

---

## 2. 全局架构图

```
                      ┌─────────────────────────────────────────┐
                      │           本地开发流程                    │
                      │                                          │
   浏览器 ──▶ http://localhost:3000/giffgaff                     │
       │              │                                          │
       │ OAuth        ▼                                          │
       │   /bff/giffgaff-token-exchange                          │
       │              │                                          │
       │              ▼  server.js (Express)                     │
       │     注入 x-esim-key                                      │
       │              │                                          │
       │              ▼  /.netlify/functions/giffgaff-token-…    │
       │     读取 .env: CLIENT_ID + CLIENT_SECRET                 │
       │              │                                          │
       │              ▼  Basic Auth header                       │
       │     POST https://id.giffgaff.com/auth/oauth/token       │
       │                                                         │
       └─────────────────────────────────────────────────────────┘
```

---

## 3. 前置条件

| 项 | 要求 |
|----|------|
| macOS | 任意现代版本（脚本用 zsh） |
| Node.js | ≥ 18.0.0 |
| Java | ≥ 11（`apk-mitm` 内部调 `apktool`） |
| Homebrew | 装 `mitmproxy`、`android-platform-tools` 用 |
| Android 手机 | Android 7+，能开 USB 调试 |
| Wi-Fi | 手机和电脑必须**同一个** Wi-Fi |

---

## 4. 工具链安装

```bash
# 1. mitmproxy（拦截 HTTPS）
brew install mitmproxy

# 2. apk-mitm（自动改 APK 信任 user CA + 去 SSL Pinning）
#    注意：如果 ~/.npm 有 root 残留文件，先 sudo chown -R $(id -u):$(id -g) ~/.npm
npm install -g apk-mitm

# 3. adb（把 APK 在手机 ↔ 电脑之间搬运）
brew install --cask android-platform-tools

# 验证
mitmproxy --version
apk-mitm --version 2>&1 | head -1
adb version | head -1
```

---

## 5. 初始 `.env` 配置

```bash
cp env.example .env
```

按下表填写最小可用配置（先不填 SECRET，留到第 7 步抓包后再填）：

| 变量 | 本地建议值 | 说明 |
|------|----------|------|
| `ACCESS_KEY` | `$(openssl rand -hex 32)` 输出 | Functions / Server 共享密钥 |
| `ALLOWED_ORIGIN` | `http://localhost:3000` | 默认是线上域名，本地必须改 |
| `CAPTCHA_PROVIDER` | `off` | 默认 turnstile 需 Site Key，本地关掉 |
| `TURNSTILE_ENFORCE` | `false` | 同上 |
| `GIFFGAFF_CLIENT_ID` | `4a05bf219b3985647d9b9a3ba610a9ce` | 直接抄。前端代码已硬编码：[api-config.js](../../src/giffgaff/js/modules/api-config.js) |
| `GIFFGAFF_CLIENT_SECRET` | （第 7 步抓） | **必须 Base64、长度 ≥32**，否则 [giffgaff-token-exchange.js](../../netlify/functions/giffgaff-token-exchange.js) 报 500 |
| `GIFFGAFF_REDIRECT_URI` | `giffgaff://auth/callback/` | 一般无需改 |
| `SIMYO_CLIENT_TOKEN` | （只用 Giffgaff 可空） | Simyo 工具才需要 |

---

## 6. 验证本地 Server

```bash
npm install            # 首次
npm run dev            # 或 npm start
```

应看到：

```
[INFO] 🚀 eSIM工具服务器已启动
[INFO] 📍 本地地址: http://localhost:3000
```

浏览器打开 http://localhost:3000/giffgaff，看到 UI 即 OK。此时 OAuth 跳转能正常发起，但**点登录后回调那一步会因为没填 SECRET 失败**。

---

## 7. 抓 `GIFFGAFF_CLIENT_SECRET`（核心）

### 7.1 准备 mitmproxy 自动提取脚本

在项目根目录创建工作区（已加入 `.gitignore`）：

```bash
mkdir -p .sniff
```

把以下脚本保存为 `.sniff/extract_giffgaff_secret.py`：

```python
"""mitmproxy addon: 命中 Giffgaff OAuth token 请求时自动解码 Basic Auth"""
import base64, datetime
from pathlib import Path
from mitmproxy import http, ctx

OUT_FILE = Path(__file__).parent / "giffgaff_credentials.txt"

def request(flow: http.HTTPFlow) -> None:
    if flow.request.host != "id.giffgaff.com":
        return
    if flow.request.path.split("?", 1)[0] != "/auth/oauth/token":
        return
    auth = flow.request.headers.get("Authorization", "")
    if not auth.lower().startswith("basic "):
        return
    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
    if ":" not in decoded:
        return
    cid, secret = decoded.split(":", 1)
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    msg = (f"\n{'='*60}\n✅ 抓到 Giffgaff 凭据 @ {ts}\n"
           f"GIFFGAFF_CLIENT_ID={cid}\nGIFFGAFF_CLIENT_SECRET={secret}\n{'='*60}\n")
    ctx.log.alert(msg)
    print(msg, flush=True)
    OUT_FILE.write_text(
        f"# {ts}\nGIFFGAFF_CLIENT_ID={cid}\nGIFFGAFF_CLIENT_SECRET={secret}\n",
        encoding="utf-8")
```

### 7.2 启动 mitmproxy

```bash
# 找本机局域网 IP（手机配代理要用）
ifconfig | awk '/^[a-z]/{i=$1} /inet /{ if($2!="127.0.0.1" && $2!~/^169\./) print i,$2 }'
# 假设输出 en1 192.168.x.x，下面以这个为例

# 启动 mitmproxy（同时跑 Web UI 方便观察）
mitmweb -s .sniff/extract_giffgaff_secret.py \
        --listen-host 0.0.0.0 --listen-port 8080 \
        --web-host 127.0.0.1 --web-port 8081 \
        --no-web-open-browser
```

浏览器打开 http://127.0.0.1:8081 看流量面板。

### 7.3 手机配 Wi-Fi 代理

1. Wi-Fi 列表 → 长按当前网络 → 修改网络 → 高级 → **代理 = 手动**
2. 主机名：`192.168.x.x`（上一步的电脑 IP）
3. 端口：`8080`
4. 保存

### 7.4 手机装 mitmproxy CA 证书

> 这一步只是让**系统/浏览器**信任 mitmproxy；Android 7+ 的应用还需要第 7.5 步的 APK 改造才能解密 App 内 HTTPS。

1. 手机自带浏览器打开 **http://mitm.it**（注意是 HTTP）
2. 点 **Android** → 下载 `.pem` 证书
3. 系统设置 → 安全 → 加密与凭据 → **安装证书** → **CA 证书** → 选刚下的文件
4. 系统弹"会监控你的网络" → **继续**
5. 验证：手机浏览器访问 `https://example.com`，能打开即通

### 7.5 用 `apk-mitm` 改造 Giffgaff App

```bash
cd .sniff

# 1. 拉手机上已装的 Giffgaff APK
PKG=com.giffgaffmobile.controller
APK_PATH=$(adb shell pm path $PKG | tr -d '\r' | sed 's/package://')
adb pull "$APK_PATH" giffgaff.apk

# 2. apk-mitm 自动改 network_security_config + 去 SSL Pinning + 重签名
apk-mitm giffgaff.apk
# 完成后会生成 giffgaff-patched.apk
```

### 7.6 装回手机

> ⚠️ 因为签名变了（debug keystore），必须先卸载官方版。会清掉 App 本地数据，但 eSIM/账号数据都在 Giffgaff 服务端，重新登录即可。

```bash
adb uninstall com.giffgaffmobile.controller
adb install -r giffgaff-patched.apk
```

**华为/荣耀机型若报 `INSTALL_FAILED_USER_RESTRICTED`：** 打开「开发者选项 → 通过 USB 安装应用」（HarmonyOS 不同版本名称略异）。

### 7.7 在 App 内登录一次

1. 解锁手机，打开"Giffgaff"图标（patched 版图标和原版一样）
2. **再次确认手机 Wi-Fi 代理还是 `192.168.x.x:8080`**（部分手机重启会重置）
3. 输入账号密码登录，走到主界面或 MFA 即可

mitmproxy 终端会打印类似：

```
✅ 抓到 Giffgaff 凭据 @ 2026-05-21T13:10:19
GIFFGAFF_CLIENT_ID=4a05bf219b3985647d9b9a3ba610a9ce
GIFFGAFF_CLIENT_SECRET=<44 字符 Base64 字符串>
```

文件同步写到 `.sniff/giffgaff_credentials.txt`。

### 7.8 写入 `.env` 并重启

```bash
# 取出 secret
SECRET=$(grep '^GIFFGAFF_CLIENT_SECRET=' .sniff/giffgaff_credentials.txt | cut -d= -f2-)

# 写入 .env（macOS 用 -i ''；Linux 用 -i）
sed -i '' "s|^GIFFGAFF_CLIENT_SECRET=.*|GIFFGAFF_CLIENT_SECRET=$SECRET|" .env

# 重启 server
lsof -ti:3000 | xargs -r kill -9
npm run dev
```

### 7.9 端到端验证

```bash
# 用一个伪造的 code 请求 token-exchange
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"code":"fake_code_xxxxxxxxxxxxx","code_verifier":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","redirect_uri":"giffgaff://auth/callback/"}' \
  -w "\nHTTP %{http_code}\n" \
  http://localhost:3000/bff/giffgaff-token-exchange
```

**预期**：HTTP 400 + `AxiosError: Request failed with status code 400` ← Giffgaff 真实拒绝伪 code 的回应。
**不应该**看到：`GIFFGAFF_CLIENT_SECRET 未配置`（说明 secret 没生效）或 `404 Not Found`（说明 `/bff/*` 路由没挂）。

到这里浏览器走真实 OAuth 流程能完整跑通，access_token 拿得到，后续 GraphQL / MFA / eSIM 操作可用。

---

## 8. 收尾清理（重要）

| 项 | 必要性 | 操作 |
|----|--------|------|
| 取消手机 Wi-Fi 代理 | **必做** | 否则关电脑后手机上不了网。Wi-Fi 设置 → 代理 → 无 |
| 卸载手机 mitmproxy CA | 建议 | 设置 → 安全 → 加密与凭据 → 用户凭据 → 删除 mitmproxy |
| 恢复手机官方 Giffgaff | 建议 | `adb uninstall com.giffgaffmobile.controller` 后从应用市场重装 |
| 关闭 mitmproxy | 推荐 | `lsof -ti:8080,8081 \| xargs kill` 或直接关终端 |
| `.sniff/` 目录 | 保留 | 已在 `.gitignore`；secret 失效时再跑一次同样脚本 |
| `.env` | **绝不提交** | 已在 `.gitignore`，但 `git status` 再确认一次 |

---

## 9. 故障排查

### `npm run dev` 报 `Logger.log is not a function`
本仓库已修：[server.js](../../server.js) 把 `require('./src/js/modules/logger.js')` 改成 `require('./scripts/logger.js')`。前者是前端 ES6 module，CommonJS `require` 拿不到。

### 浏览器报 `POST /bff/giffgaff-token-exchange 404`
本仓库已修：[server.js](../../server.js) 用循环同时挂了 `/.netlify/functions/*` 和 `/bff/*` 两套路径，本地模拟 Edge BFF 代理行为。

### `GIFFGAFF_CLIENT_SECRET 格式无效：必须为 Base64 编码`
说明你抓到的 secret 不是 Base64 字符。检查 `Authorization: Basic` 头的解码逻辑——Basic Auth 里冒号后面那段本身就应该是 Base64 形式的字符串（Giffgaff 的就是）。

### `GIFFGAFF_CLIENT_SECRET 长度过短：必须至少32字符`
同上，secret 抓错了，或者抓的是别的请求（比如刷新 token 用的）。只看 `/auth/oauth/token` 的 `grant_type=authorization_code` 那次。

### App 登录后没看到 mitmproxy 命中
按顺序检查：
1. 手机能不能上网？（验证 Wi-Fi 代理仍生效）
2. mitmproxy Web UI（http://127.0.0.1:8081）有没有任何流量？没有 → 代理没生效
3. 有流量但没 Giffgaff 的 → App 没走代理（SSL Pinning 没去干净，回到 7.5 重新 apk-mitm，必要时加 `--debuggable` 或 `--skip-patches` 调试）
4. 有 Giffgaff 流量但没 `/auth/oauth/token` → App 没走到登录这一步，重新走流程

### `apk-mitm` 失败 `Failed to decode resources.arsc`
通常是 apktool 版本和 APK 太新不兼容。装最新版 apktool 后用 `apk-mitm --apktool /path/to/apktool.jar giffgaff.apk` 指定。

### Android 7+ 装好 CA 还是不抓 App 流量
这是预期——Android 7+ 应用默认不信任用户 CA，必须经过 7.5 的 apk-mitm 改造。系统/浏览器流量能抓不代表 App 流量能抓。

---

## 10. 安全声明

- 本攻略用于**用户在自己的设备、自己的账号**上对自己的 OAuth 凭据进行抓取，用于本地开发联调
- 抓到的 `client_secret` 是 Giffgaff Android App 的内置凭据，**不要在公开场合分享**（违反 Giffgaff 服务条款）
- 不要把 `.env` / `.sniff/giffgaff_credentials.txt` 提交到 git
- 改造后的 patched APK 仅作抓包用途，**不要长期使用**（已禁用 SSL Pinning 等于失去一道安全防护）
- Giffgaff 可能在新版 App 中轮换 secret，届时重跑一次本流程即可
