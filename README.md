# Rauthy SSO for Emby

通过标准 OpenID Connect 登录 Emby Web，并支持自动创建、绑定和解绑 Emby 账号。Rauthy 是主要测试目标，但任何符合 OIDC 且使用 RSA 签名（RS256/RS384/RS512）的身份提供商都可以尝试。

## 功能

- 电脑／电视客户端一次性登录码：6 位数字、5 分钟有效、本地密码保留

- `/sso` 登录入口，使用 Authorization Code + PKCE（S256）
- 在 Emby 登录页和手动登录页显示“使用 SSO 登录”按钮
- 首次 SSO 登录可自动创建受限的 Emby 用户
- 支持把 SSO 身份绑定到已有 Emby 账号，保留观看记录和权限
- 支持用本地密码验证后解除绑定
- 管理员可配置允许的媒体库、必需声明、已验证邮箱等
- 登录会话直接写入 Emby Web 的 `servercredentials3`，无需修改 Emby 本身

## 重要限制

- **客户端登录码**：支持在电脑／电视客户端密码框输入一次性登录码；普通用户和管理员均可使用。客户端需支持手动添加服务器及用户名／密码登录。详见[客户端登录码](docs/client-login-code.md)。
- **本地登录仍然可用**。插件不强制所有用户使用 SSO；管理员账号也可以绑定并使用 SSO。
- 管理员使用 SSO 时，Rauthy 账户的安全性等同于 Emby 管理员权限；请确保 IdP 启用了 MFA 和严格策略。
- 没有实现 RP-initiated logout、会话撤销或 SSO 会话与 Emby 会话的联动。
- 没有管理员端的绑定列表/审计界面；绑定数据保存在 `bindings.json`。

## 环境要求

- Emby Server 4.10.x（已在 4.10.2.0 上测试）
- .NET 8 SDK（构建插件和测试）
- Python 3.10+（测试脚本）
- Node.js 18+ 与 Playwright（仅浏览器端到端测试）
- OpenSSL（仅浏览器测试生成本地证书）
- Rauthy 或其他 OIDC 提供商，客户端签名算法使用 **RS256/RS384/RS512**（不支持 EdDSA）

## 构建

```bash
dotnet build src/EmbySso/EmbySso.csproj -c Release --no-restore
```

Release 构建会通过 ILRepack 把 IdentityModel 等依赖合并，输出：

```text
artifacts/EmbySso.dll
```

如果本机没有还原过 NuGet 包，先运行：

```bash
python scripts/fetch-packages.py
dotnet restore
```

`scripts/fetch-packages.py` 会把固定版本的构建依赖下载到 `.cache/feed`；仓库根目录的 `NuGet.config` 已包含这个本地源。

## 安装

1. 停止 Emby Server。
2. 把 `artifacts/EmbySso.dll` 复制到 Emby 的 plugins 目录，例如：
   - Windows：`%APPDATA%\Emby-Server\programdata\plugins\`
   - Linux：`/var/lib/emby/plugins/`
3. 启动 Emby，在 Dashboard → Advanced → Plugins 中打开 **Rauthy SSO** 配置。

插件启动时会向 Emby 安装目录的 `dashboard-ui/index.html` 注入一行脚本：

```html
<script defer src="../sso/assets/entry.js"></script>
```

`entry.js` 在 Emby 登录页/手动登录页显示“使用 SSO 登录”按钮，并在个人配置页加入原生样式的 SSO 绑定表单。Emby 进程需要对安装目录有写权限；没有写权限时，可以使用下面的反向代理方式注入脚本。

## Rauthy 配置

在 Rauthy 中创建一个 OIDC 客户端：

- **Redirect URI**：`{PublicUrl}/sso/callback`
  - 例如 `https://emby.example.com/sso/callback`
  - 如果 Emby 部署在反向代理的子路径下，例如 `https://emby.example.com/media`，则为 `https://emby.example.com/media/sso/callback`
- **Client Authentication**：`client_secret_basic`（推荐）或 `client_secret_post`
  - 公共客户端也可以选 `none`，此时仍使用 PKCE
- **ID Token Algorithm**：`RS256`（推荐）、`RS384` 或 `RS512`；当前不支持 EdDSA
- **Scopes**：至少 `openid`；建议 `openid profile email`
- 如果使用访问限制，确认 ID Token 中包含对应的声明，例如 `roles`

Rauthy 的 issuer 通常带末尾斜杠，例如：

```text
https://auth.example.com/auth/v1/
```

插件配置中的 Issuer 必须与发现文档中的 `issuer` **完全一致**，包括末尾斜杠。

Rauthy 的发现文档通常发布在域名根路径：

```text
https://auth.example.com/.well-known/openid-configuration
```

如果实际地址不同，在插件中填写“发现文档地址”。该地址必须与 Issuer 同源且为 HTTPS。

## 插件配置

| 字段 | 说明 |
| --- | --- |
| 启用 SSO | 关闭后 `/sso` 不可用 |
| 允许不安全 HTTP | 仅测试/可信内网使用。允许 PublicUrl、Issuer、发现文档和 OIDC 端点使用 `http://`；Token 和 Emby AccessToken 会明文传输 |
| Emby 公开地址 | 默认必须是 HTTPS 地址，可包含反向代理路径前缀，不含 `/web`；登录入口为此地址加 `/sso`。启用不安全 HTTP 后也可以是 `http://` |
| Rauthy Issuer | 必须与发现文档的 `issuer` 完全一致 |
| 发现文档地址 | 可选；留空时使用 Issuer 所在域名根路径的 `/.well-known/openid-configuration` |
| Client ID | OIDC 客户端 ID |
| Client Secret | 机密客户端密钥；公共客户端可留空 |
| 客户端认证方式 | `client_secret_basic`、`client_secret_post` 或 `none` |
| Scopes | 空格分隔，必须包含 `openid` |
| 首次 SSO 登录自动创建用户 | 关闭后，未绑定的用户必须先用现有账号绑定 |
| 要求已验证邮箱 | 要求 ID Token 中 `email_verified` 为 JSON `true` |
| 访问限制声明名称/允许值 | 例如 `roles` / `emby`；两者要么都留空，要么都填写 |
| 新用户媒体库 ID | 逗号分隔；留空表示新账号没有任何媒体库权限；只影响新账号 |

新账号默认是非管理员、受限权限、策略中标记为隐藏（`IsHidden` / `IsHiddenRemotely`），并且不会自动获得全部媒体库权限。

设置页会跟踪未保存的修改。Emby 在应用恢复/窗口重新获得焦点时可能刷新当前视图；插件不会用服务端配置覆盖尚未保存的填写内容，而是保留草稿并显示提示。页面完全刷新或关闭标签页后，未保存的修改仍会丢失。

## 使用

1. 浏览器打开 `{PublicUrl}/sso`。
2. 点击“通过 SSO 登录”。
3. 首次登录时：
   - 开启自动创建：如果用户名不存在，会创建一个受限 Emby 账号并绑定。
   - 用户名已存在：先使用原账号登录 Emby，再进入个人配置页面绑定。
4. 绑定现有账号：在个人配置页面的“SSO 账号绑定”中，仅输入本地密码，再跳转 SSO 授权。用户名由当前登录会话自动确定。
5. 解除绑定：在同一位置输入本地密码并点击“解除 SSO 绑定”，完成后仍留在个人配置页面。

详见[个人配置页绑定说明](docs/profile-binding.md)。

自动创建的账号会获得一个随机初始密码，因此：

- 通过 SSO 登录 Emby Web 后，建议先在 Emby 用户设置里设置自己的本地密码，再使用解绑功能。
- Emby 4.10.2 的自我修改密码页面在 4.8.0.38 及以上版本不会要求当前密码；如果版本较旧或无法修改，请让管理员重置密码。

## 反向代理示例

以下示例把 Emby 挂在 `https://emby.example.com/media/`：

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name emby.example.com;

    location /media/ {
        proxy_pass http://127.0.0.1:8096/;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

对应插件配置：

```text
Emby 公开地址 = https://emby.example.com/media
Redirect URI  = https://emby.example.com/media/sso/callback
```

如果 Emby 安装目录只读，无法自动注入登录按钮，可以在反向代理中注入同一个脚本：

```nginx
sub_filter '</head>' '<script defer src="../sso/assets/entry.js"></script></head>';
sub_filter_types text/html;
sub_filter_once on;
proxy_set_header Accept-Encoding "";
```

`sub_filter` 需要 Nginx 的 `ngx_http_sub_module`；关闭上游压缩，否则无法替换。

注意：

- 反向代理必须保留浏览器发送的 `Host`，不能改写成内部地址；插件会用 Host 和 Origin 校验公开地址。
- 不要删除 `Origin` 请求头，否则 `/sso/start` 和 `/sso/session` 会被拒绝。
- 路径前缀由代理剥离；如果代理不剥离前缀，Emby 不会匹配 `/sso` 路由。
- 插件限流使用 `Request.RemoteIp`；在反向代理后面，多个用户可能共享代理 IP 的限流额度。

## HTTP 模式（不推荐）

默认配置强制 HTTPS，因为授权码、Token、Client Secret 和 Emby AccessToken 都会经过浏览器与服务器之间的连接。仅在本地测试或完全可信的内网中，才可以开启：

- 插件配置 → **允许不安全 HTTP（仅测试/可信内网）**
- 然后 PublicUrl、Issuer、发现文档和 OIDC 端点才允许使用 `http://`

开启后的行为：

- 当 `PublicUrl` 是 `http://` 时，插件改用名为 `EmbySso` 的 Cookie，并去掉 `Secure` 属性（浏览器不允许非 HTTPS 页面使用 `__Secure-` Cookie）
- 当 `PublicUrl` 是 `https://` 时，仍然使用 `__Secure-EmbySso` 和 `Secure`，即使开关打开
- Host、Origin、CSP 和 OIDC 端点校验会接受对应的 HTTP 地址
- Rauthy 客户端也必须允许 `http://.../sso/callback` 作为 Redirect URI；部分 IdP 只允许 HTTPS（localhost 例外视配置而定），这种情况下插件开关无法绕过

**HTTP 模式下，同一网络中的任何人都可能读取授权码、ID Token、Client Secret 和登录后的 Emby AccessToken。生产环境请使用 HTTPS。**

测试脚本也支持 HTTP 模式：

```bash
python scripts/run-live-test.py --insecure-http
```

## 安全设计

- Authorization Code + PKCE S256，state 和 nonce 均为服务端生成的随机值
- state、CSRF、回调 ticket、session ticket 都是一次性、有期限、绑定浏览器 Cookie 的服务端票据
- 浏览器 Cookie：`__Secure-EmbySso`，`Secure`、`HttpOnly`、`SameSite=Lax`
- `/sso/start` 和 `/sso/session` 校验 `Host`、`Origin` 和请求体大小
- 页面使用 CSP、`X-Content-Type-Options: nosniff`、`Cache-Control: no-store`
- ID Token 校验签名、issuer、audience、nonce、iat、exp、azp、可选邮箱/声明
- 默认强制 HTTPS；只有显式开启“允许不安全 HTTP”后才接受 `http://`，此时 Cookie 自动降级为非 `__Secure-` 名称
- 管理员和普通用户使用同一套 OIDC 校验和会话策略；管理员使用 SSO 时请把 Rauthy 视为管理员凭据系统
- Emby access token 不放在 URL、回调地址、Cookie 或日志中
- 回调页在读取授权码后会立即用 `history.replaceState` 移除 URL 中的 code
- 绑定文件损坏时拒绝启动绑定存储，不会用空数据覆盖
- 错误日志只记录异常类型，不记录 token 或客户端密钥

`Referrer-Policy` 使用 `origin` 而不是 `no-referrer`：Chromium 在 `no-referrer` 下会对同源表单 POST 发送 `Origin: null`，从而被插件的 Origin 校验拒绝；`origin` 只发送来源，不发送路径和查询参数，因此回调 URL 中的授权码不会进入 Referer。

## 测试

### 单元测试

```bash
dotnet run --project tests/EmbySso.Tests -c Release --no-restore
```

覆盖配置校验、PKCE/ID Token 校验、票据、限流、绑定存储、并发创建、显式绑定、禁用/删除账号、失败回滚和默认端口归一化等。

### 隔离 Emby 集成测试

```bash
python scripts/run-live-test.py
```

脚本会：

1. 在 `.cache/live-test-data` 创建一次性 Emby 数据目录
2. 构建 Release 插件和 `EmbySso.LiveHarness`（TEST ONLY）
3. 在 18996 启动隔离 Emby，安装插件和测试 harness
4. 运行 `tests/live-http.py`：注册、重复登录、绑定、已绑定登录、CSRF、跨浏览器回调、重放、权限
5. 启动本地 HTTPS 代理（18997）并运行 `tests/browser/e2e.js`：真实浏览器完成 `/sso` → 假 IdP → 回调 → `finish.js` → Emby Web 自动登录；验证 Emby 登录页的 SSO 按钮；打开管理端插件配置页验证页面可见、配置能加载、未保存修改能在视图刷新后保留
6. 停止 Emby，删除测试数据

常用参数：

```bash
python scripts/run-live-test.py --no-browser   # 只跑 HTTP 集成测试
python scripts/run-live-test.py --insecure-http # 用 http:// PublicUrl 跑完整测试（不启动 TLS 代理）
python scripts/run-live-test.py --keep         # 保留测试数据和日志
python scripts/run-live-test.py --no-build     # 复用当前 artifacts
python scripts/run-live-test.py --http-port 18996 --https-port 18997
python scripts/run-live-test.py --emby /path/to/emby/system
```

如果 `.cache/emby/system` 不存在，脚本会尝试用 7-Zip 解压 `.cache/emby-4.10.2.0.7z`。也可以手动放置 Emby 4.10.2.0 的 `system` 目录并通过 `--emby` 指定。

浏览器测试需要 Playwright：

```bash
cd tests/browser
npm install
```

默认使用系统安装的 Chrome；可以通过 `EMBY_SSO_BROWSER_CHANNEL` 或 `PLAYWRIGHT_CHROMIUM_EXECUTABLE` 指定其他浏览器。若使用 Playwright 自带的 Chromium：

```bash
cd tests/browser
npx playwright install chromium
cd ../..
EMBY_SSO_BROWSER_CHANNEL=bundled python scripts/run-live-test.py
```

浏览器测试需要 OpenSSL 生成 `localhost` 测试证书；Git for Windows 自带 OpenSSL。

`tests/EmbySso.LiveHarness` 是 **TEST ONLY** 组件，绝不能安装到生产 Emby。

## 项目结构

```text
src/EmbySso/                插件源码
  Web/                      配置页、登录门户、完成页和静态资源
tests/EmbySso.Tests/        单元测试（自定义测试运行器）
tests/EmbySso.LiveHarness/  隔离 Emby 测试用的假 OIDC 提供商（TEST ONLY）
tests/browser/              Playwright 浏览器端到端测试
tests/live-http.py          HTTP 集成测试
scripts/run-live-test.py    构建 + 启动 + 测试 + 停止
scripts/fetch-packages.py   下载固定版本 NuGet 依赖到本地源
artifacts/EmbySso.dll       构建产物
```

绑定数据默认位于 Emby 数据目录：

```text
data/emby-sso/bindings.json
```

请把它纳入备份；文件损坏时插件会拒绝加载绑定数据。

## 兼容性说明

- 测试目标：Emby Server **4.10.2.0**
- 编译 SDK：`MediaBrowser.Server.Core` 4.10.0.24-beta2
- Emby 4.10 的插件配置页使用 `data-controller="__plugin/<name>js"` 的 view 片段格式；旧式 `data-role="page"` 全页 HTML 会被加载但保持 `page-hidden`，表现为设置页一片空白。本插件的配置页已改为 `configuration.html` + `configuration.js` 控制器模块
- 登录页按钮通过 `IServerEntryPoint` 在启动时向 `dashboard-ui/index.html` 注入 `entry.js`；Emby 升级覆盖 web 文件后，下次启动会重新注入
- 配置页的 JS 控制器通过 `Plugin.GetPages()` 以 `rauthyssojs` 名称注册，和内置插件（如 `embybackupjs`）的模式一致
- Emby Web 4.10.2.0 把登录凭据保存在 localStorage 的 `servercredentials3`
- `finish.js` 写入的字段与 Emby 的 `updateUserAuthenticationInfoOnServer` 保持一致：
  - `Server.Id`
  - `Server.ManualAddress` / `Server.ManualAddressOnly`
  - `Server.UserId`（`autoLogin=lastuser` 依赖此字段）
  - `Server.Users[].UserId` / `Server.Users[].AccessToken`
- Emby Web 的 `ConnectionManager` 使用 `server.UserId` 找到上次登录用户；缺少该字段会落到登录/选用户页
- 创建会话时 `AppVersion` 取自运行中的 Emby `IApplicationHost.ApplicationVersion`
- PublicUrl 显式写 `:443` 时，Host/Origin 比较会忽略默认端口，避免浏览器省略端口导致误判

## 故障排查

| 现象 | 排查方向 |
| --- | --- |
| “请从配置的公开 Emby 地址打开 SSO 页面” | PublicUrl 与浏览器地址不一致；代理改写了 Host；检查默认端口和路径前缀 |
| “请求来源无效” | 代理删除了 Origin；浏览器与 PublicUrl 不同源；请求体过大；HTTP 模式未勾选“允许不安全 HTTP” |
| HTTP 模式下 Cookie 失效 | 确认已勾选并保存“允许不安全 HTTP”，PublicUrl 是 `http://...`；插件会把 Cookie 名降级为 `EmbySso` |
| Rauthy 拒绝 HTTP Redirect URI | 在 Rauthy 客户端中允许 `http://.../sso/callback`，或改用 HTTPS；这不受插件控制 |
| “配置已改变，请重新打开登录页” | 登录过程中管理员保存了插件配置；重新打开 `/sso` |
| “账号验证失败” | 绑定/解绑输入的 Emby 本地密码错误 |
| “此 Emby 账号已停用” | 在 Emby 用户设置中启用该账号 |
| “此 Emby 账号当前不在允许访问时段” | 调整该用户的访问时间表（Access Schedule） |
| “此账号的远程访问或设备策略不允许本次登录” | 用户策略关闭了远程访问，或限制了设备 |
| “Issuer 与发现文档不一致” | Issuer 末尾斜杠/路径不一致；检查 Rauthy issuer |
| “未发现 RSA 签名密钥” | Rauthy 客户端 ID Token Algorithm 不是 RSA 算法；改为 RS256/RS384/RS512 |
| “ID Token 的签名密钥不在 JWKS 中” / 登录未完成 | 客户端 ID Token Algorithm 可能是 EdDSA，或使用了 JWKS 中不存在的密钥；改为 RS256（推荐）/RS384/RS512 |
| 浏览器测试停在 `/sso/start` | 检查代理是否保留 Origin，或 Referrer-Policy 是否被改成 `no-referrer` |
| Emby 登录页没有 SSO 按钮 | 确认安装的是最新 DLL 并重启过 Emby；检查 `dashboard-ui/index.html` 是否包含 `sso/assets/entry.js`；Network 中检查 `entry.js` 是否 200；安装目录只读时使用上面的 `sub_filter` 方式 |
| Rauthy SSO 设置页一片空白 | 确认安装的是最新 `artifacts/EmbySso.dll` 并已重启 Emby；确认当前用户是管理员；在开发者工具 Network 中检查 `/web/ConfigurationPage?name=rauthy-sso` 和 `?name=rauthyssojs` 是否返回 200；旧版全页 HTML 格式在 Emby 4.10 会保持 `page-hidden` |
| 窗口失焦后填写内容消失 | 使用最新 DLL；旧版配置页在 Emby 刷新视图时会重新加载服务端配置。新版会保留未保存草稿；完全刷新页面仍会丢失未保存内容 |
