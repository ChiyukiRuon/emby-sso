# 电脑与电视客户端登录码

已登录 Emby 且已绑定 SSO 的普通用户和管理员，均可直接获取一次性 PIN 码，在客户端密码框使用。

## 使用步骤

1. 安装新版插件并重启 Emby。
2. 在同一个浏览器中登录 Emby，并在个人配置页面绑定 SSO。
3. 点击右上角用户头像，在菜单中选择“生成 PIN 码”（也可直接打开 `{PublicUrl}/sso`），页面验证现有登录会话后直接显示服务器地址、用户名和 **6 位 PIN 码**。
4. 未登录或会话失效时禁止访问；未绑定时提示先绑定并提供个人配置入口。
5. 电脑或电视客户端选择手动连接服务器，填写服务器地址、用户名，在密码栏输入 PIN 码。
6. 需要新码时点击“重新生成 PIN 码”；旧码立即失效。

这是本地 Emby 用户名／密码登录，不是 Emby Connect PIN 登录；不要将登录码输入 Emby Connect 页面。用户名使用页面显示的 Emby 用户名。

登录码有效期为 5 分钟，每个账号同时只有一个有效码。重新生成会使旧码失效，成功验证一次后立即失效。若设备策略阻止了后续会话创建，也可能需要重新生成。登录成功后由客户端保存普通 Emby 会话，无需每次播放都输入新码；若客户端需要重新认证，应生成新码。

## 权限与本地密码

- 管理员登录后保留管理员权限，普通用户权限不会提升。
- 首次生成登录码时，该账号的认证提供器设为 SSO login code + local password；本地密码与修改密码能力保留。
- 禁用账号、关闭远程访问、设备限制仍会阻止相应登录。
- 使用其他认证提供器（例如 LDAP）的账号不会被自动切换，页面会提示无法生成登录码。
- 绑定／解绑仍要求本地密码，不能使用一次性码代替。
- 解绑会撤销尚未兑换的码。配置变化、过期、插件重启均会使码失效；关闭 SSO 时不接受登录码。
- 码仅以哈希保存在内存中，不写入文件。每个账号每五分钟最多生成 10 次码、尝试 10 次数字码验证。
- 码兑换产生的是普通 Emby 会话；码过期、解绑或关闭 SSO 不会撤销已经创建的客户端会话。

如果卸载插件，应先在 Emby 用户管理中把已启用此功能的用户的认证提供器改回默认本地认证；原有本地密码没有被替换。仅关闭插件内的“启用 SSO”开关时，提供器仍可验证本地密码。

## 验证范围

使用 Emby Server 4.10.2.0 的真实 Users/AuthenticateByName 接口验证普通用户、管理员、本地密码兼容、码重放和重新生成，以及权限限制。浏览器测试覆盖 SSO 到码展示再到标准客户端认证。

尚未在具体品牌电视或桌面原生 App 上手工验证。客户端必须把密码通过标准认证接口提交，并保存返回的 Emby 会话；仅支持 Emby Connect 或仅提交旧式密码摘要的客户端不在支持范围。

实现依据 Emby 官方 [IAuthenticationProvider](https://dev.emby.media/reference/pluginapi/MediaBrowser.Controller.Authentication.IAuthenticationProvider.html)、[IRequiresResolvedUser](https://dev.emby.media/reference/pluginapi/MediaBrowser.Controller.Authentication.IRequiresResolvedUser.html) 与 [IApplicationHost](https://dev.emby.media/reference/pluginapi/MediaBrowser.Common.IApplicationHost.html) 接口；版本行为以隔离集成测试为准。

直接导航 `/sso` 返回不包含凭据或 PIN 的 401 验证页面。浏览器读取当前服务器的已有会话，通过需要 Emby 身份验证的 `POST /sso/code` 获取 PIN；接口同时验证来源和绑定状态。Emby 登录页的 SSO 按钮使用独立的 `/sso/start` 接口。
