using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using MediaBrowser.Common;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Services;

namespace EmbySso;

public sealed class SsoService : IService, IHasResultFactory
{
    private const string SecureCookieName = "__Secure-EmbySso";
    private const string InsecureCookieName = "EmbySso";
    private readonly IUserManager users;
    private readonly IAuthorizationContext authorization;
    private readonly ISessionManager sessions;
    private readonly ILogger logger;
    private readonly Plugin plugin;
    private readonly EmbyGateway gateway;
    private readonly Accounts accounts;
    private readonly string appVersion;
    public IRequest Request { get; set; } = null!;
    public IHttpResultFactory ResultFactory { get; set; } = null!;

    public SsoService(IUserManager users, ISessionManager sessions, ILogManager logs,
        IHttpResultFactory resultFactory, IApplicationHost appHost, IAuthorizationContext authorization)
    {
        this.users = users;
        this.authorization = authorization;
        this.sessions = sessions;
        ResultFactory = resultFactory;
        logger = logs.GetLogger("EmbySso");
        plugin = Plugin.Instance;
        gateway = new EmbyGateway(users);
        // Keep the session's client version in sync with the server that is actually running.
        appVersion = appHost.ApplicationVersion?.ToString() ?? "unknown";
        lock (plugin) accounts = plugin.Accounts ??= new Accounts(gateway, plugin.Bindings);
    }

    public object Get(PortalRequest request) => Guard(() =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckHost(config);
        plugin.Limiter.Check("page:" + Request.RemoteIp, 60);
        var browser = EnsureBrowser(config);
        var csrf = plugin.Forms.Add(browser, config.Fingerprint);
        return Page("portal.html", config, new { csrf, publicUrl = config.PublicUrl.TrimEnd('/') });
    });

    public object Get(AssetRequest request) => Guard(() =>
    {
        if (request.Name is not ("portal.js" or "finish.js" or "portal.css" or "entry.js"))
            throw new SsoException("资源不存在。");
        Headers();
        return Content(Resource(request.Name), request.Name.EndsWith(".css", StringComparison.Ordinal) ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8");
    });

    public Task<object> Post(StartRequest request) => GuardAsync(async () =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckPost(config);
        var browser = Browser(config, true);
        plugin.Limiter.Check("start:" + Request.RemoteIp);
        var fingerprint = plugin.Forms.Take(Bounded(request.Csrf, 128), browser);
        if (fingerprint != config.Fingerprint) throw new SsoException("配置已改变，请重新打开登录页。");
        if (request.Action != "login") throw new SsoException("请在个人配置页面管理 SSO 绑定。");
        var flow = new OidcFlow(config, Secrets.Random(), Secrets.Random(), null);
        var state = plugin.Flows.Add(browser, flow);
        var url = await plugin.Oidc.AuthorizationUrl(flow, state, Request.CancellationToken);
        Headers();
        return ResultFactory.GetRedirectResult(url);
    });

    public Task<object> Get(CallbackRequest request) => GuardAsync(async () =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckHost(config);
        plugin.Limiter.Check("callback:" + Request.RemoteIp, 40);
        var browser = Browser(config, true);
        var flow = plugin.Flows.Take(Bounded(request.State, 128), browser);
        if (flow.Configuration.Fingerprint != config.Fingerprint) throw new SsoException("配置已改变，请重新开始登录。");
        if (!string.IsNullOrEmpty(request.Error)) throw new SsoException("SSO 登录已取消或被拒绝，请重新开始。");
        if (!string.IsNullOrEmpty(request.Iss) && request.Iss != config.Issuer)
            throw new SsoException("回调的身份提供商不匹配。");
        var code = Bounded(request.Code, 4096);
        if (code.Length == 0) throw new SsoException("回调缺少授权码。");
        var identity = await plugin.Oidc.Exchange(flow, code, Request.CancellationToken);
        var account = await accounts.Resolve(identity, flow.LinkUserId, config);
        if (flow.LinkUserId != null)
        {
            Headers();
            return ResultFactory.GetRedirectResult(config.PublicUrl.TrimEnd('/') + "/web/index.html#!/settings/profile.html?userId=" + account.Id);
        }
        var ticket = plugin.Sessions.Add(browser, new SessionTicket(account.Id, config.Fingerprint), TimeSpan.FromSeconds(60));
        return Page("finish.html", config, new { ticket, publicUrl = config.PublicUrl.TrimEnd('/') });
    });

    public Task<object> Post(SessionRequest request) => GuardAsync(async () =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckPost(config);
        var browser = Browser(config, true);
        var ticket = plugin.Sessions.Take(Bounded(request.Ticket, 128), browser);
        if (ticket.ConfigurationFingerprint != config.Fingerprint) throw new SsoException("配置已改变，请重新登录。");
        var account = gateway.Find(ticket.UserId) ?? throw new SsoException("账号不存在。");
        gateway.AssertAllowed(account);
        var user = users.GetUserById(account.Id);
        var policy = users.GetUserPolicy(user);
        var deviceId = "embysso-" + Secrets.Hash(browser)[..24];
        // SSO is an external login; never let a loopback reverse proxy bypass remote-access policy.
        if (!policy.EnableRemoteAccess || (!policy.EnableAllDevices && !(policy.EnabledDevices ?? []).Contains(deviceId)))
            throw new SsoException("此账号的远程访问或设备策略不允许本次登录。");
        var result = await sessions.CreateNewSession(new AuthenticationRequest
        {
            UserId = user.InternalId, Username = user.Name, App = "Emby Web",
            AppVersion = appVersion, DeviceId = deviceId, DeviceName = "SSO Browser",
            RemoteAddress = Request.RemoteIp, Protocol = "https"
        }, Request.CancellationToken);
        Headers();
        // No Emby access token is put in a redirect URL, callback URL, cookie or log.
        return Content(JsonSerializer.Serialize(new { result.AccessToken, result.ServerId, User = new { Id = result.User.Id }, DeviceId = deviceId }), "application/json; charset=utf-8");
    });

    private string EnsureBrowser(Configuration config)
    {
        var browser = Browser(config, false);
        if (browser.Length == 0)
        {
            var cookie = Cookie(config);
            browser = Secrets.Random();
            Request.Response.AddHeader("Set-Cookie", cookie.Name + "=" + browser + "; Path="
                + new Uri(config.PublicUrl).AbsolutePath.TrimEnd('/') + "/sso"
                + (cookie.Secure ? "; Secure" : "") + "; HttpOnly; SameSite=Lax; Max-Age=1800");
        }
        return browser;
    }

    private Account CurrentAccount()
    {
        var info = authorization.GetAuthorizationInfo(Request);
        var user = users.GetUserById(info.UserId) ?? throw new SsoException("请先登录 Emby。");
        var account = EmbyGateway.Describe(user);
        gateway.AssertAllowed(account);
        return account;
    }

    public object Get(PasswordStatusRequest request) => Guard(() =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckHost(config);
        var account = CurrentAccount();
        Headers();
        return Content(JsonSerializer.Serialize(new {
            requiresPasswordChange = plugin.Bindings.RequiresPasswordChange(account.Id, gateway.PasswordFingerprint(account))
        }), "application/json; charset=utf-8");
    });

    public object Get(ProfileRequest request) => Guard(() =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckHost(config);
        var account = CurrentAccount();
        var browser = EnsureBrowser(config);
        Headers();
        return Content(JsonSerializer.Serialize(new {
            csrf = plugin.Forms.Add(browser, config.Fingerprint),
            username = account.Name,
            bound = plugin.Bindings.IsBound(config.Issuer, account.Id)
        }), "application/json; charset=utf-8");
    });

    public Task<object> Post(ProfileActionRequest request) => GuardAsync(async () =>
    {
        var config = plugin.Configuration.Snapshot();
        CheckPost(config);
        var account = CurrentAccount();
        var browser = Browser(config, true);
        plugin.Limiter.Check("start:" + Request.RemoteIp);
        var fingerprint = plugin.Forms.Take(Bounded(request.Csrf, 128), browser);
        if (fingerprint != config.Fingerprint) throw new SsoException("配置已改变，请刷新个人配置页面。");
        if (request.Action is not ("link" or "unlink")) throw new SsoException("未知操作。");
        var password = Bounded(request.Password, 1024);
        if (password.Length == 0) throw new SsoException("请输入 Emby 本地密码。");
        plugin.Limiter.Check("password:" + Secrets.Hash(account.Name.ToUpperInvariant()), 10);
        var verified = await users.AuthenticateUser(account.Name, password, true, Request.CancellationToken);
        if (verified == null || EmbyGateway.Describe(verified).Id != account.Id)
            throw new SsoException("账号验证失败。");
        gateway.AssertAllowed(account);
        Headers();
        if (request.Action == "unlink")
        {
            await accounts.Unbind(config.Issuer, account);
            return Content("{\"unlinked\":true}", "application/json; charset=utf-8");
        }
        var flow = new OidcFlow(config, Secrets.Random(), Secrets.Random(), account.Id);
        var state = plugin.Flows.Add(browser, flow);
        var url = await plugin.Oidc.AuthorizationUrl(flow, state, Request.CancellationToken);
        return Content(JsonSerializer.Serialize(new { url }), "application/json; charset=utf-8");
    });

    private void CheckHost(Configuration config)
    {
        var expected = Origins.PublicAuthority(config.PublicUrl, config.AllowInsecureHttp);
        if (expected.Length == 0
            || !string.Equals(Origins.Authority(Request.Headers["Host"] ?? ""), expected, StringComparison.OrdinalIgnoreCase))
            throw new SsoException("请从配置的公开 Emby 地址打开 SSO 页面。");
    }

    private void CheckPost(Configuration config)
    {
        CheckHost(config);
        var origin = Origins.Origin(Request.Headers["Origin"] ?? "", config.AllowInsecureHttp);
        if (origin.Length == 0
            || !string.Equals(origin, Origins.Origin(config.PublicUrl, config.AllowInsecureHttp), StringComparison.OrdinalIgnoreCase)
            || Request.ContentLength > 16384)
            throw new SsoException("请求来源无效，请重新打开登录页。");
    }

    private static (string Name, bool Secure) Cookie(Configuration config) =>
        config.PublicUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? (SecureCookieName, true)
            : (InsecureCookieName, false);

    private string Browser(Configuration config, bool required)
    {
        var name = Cookie(config).Name;
        var cookie = (Request.Headers["Cookie"] ?? "").Split(';').Select(s => s.Trim())
            .FirstOrDefault(s => s.StartsWith(name + "=", StringComparison.Ordinal));
        var value = cookie?[(name.Length + 1)..] ?? "";
        if (value.Length != 43 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            value = "";
        if (required && value.Length == 0) throw new SsoException("登录 Cookie 已失效，请允许 Cookie 并重新开始。");
        return value;
    }

    private object Page(string resource, Configuration config, object bootstrap)
    {
        Headers();
        return Content(Resource(resource).Replace("{{BASE}}", WebUtility.HtmlEncode(config.PublicUrl.TrimEnd('/')))
            .Replace("{{DATA}}", JsonSerializer.Serialize(bootstrap)), "text/html; charset=utf-8");
    }

    private object Message(string message, Configuration? config = null)
    {
        Headers();
        var back = config == null ? "" : "<p><a href=\"" + WebUtility.HtmlEncode(config.PublicUrl.TrimEnd('/') + "/sso") + "\">返回 SSO 登录</a></p>";
        return Content("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>SSO</title><body><h1>SSO</h1><p>"
            + WebUtility.HtmlEncode(message) + "</p>" + back + "</body></html>", "text/html; charset=utf-8");
    }

    private void Headers()
    {
        Request.Response.AddHeader("Cache-Control", "no-store");
        Request.Response.AddHeader("Pragma", "no-cache");
        // no-referrer makes Chromium send "Origin: null" on same-origin form POSTs, which would
        // defeat the Origin check in CheckPost. "origin" keeps that header valid while never
        // putting the callback URL's authorization code into a Referer header.
        Request.Response.AddHeader("Referrer-Policy", "origin");
        Request.Response.AddHeader("X-Content-Type-Options", "nosniff");
        var config = plugin.Configuration;
        var issuerOrigin = Uri.TryCreate(config.Issuer, UriKind.Absolute, out var issuer)
            && (issuer.Scheme == Uri.UriSchemeHttps
                || (config.AllowInsecureHttp && issuer.Scheme == Uri.UriSchemeHttp))
            ? " " + issuer.GetLeftPart(UriPartial.Authority) : "";
        Request.Response.AddHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'" + issuerOrigin + "; base-uri 'none'; frame-ancestors 'none'");
    }

    private object Content(string value, string contentType) => ResultFactory.GetResult(Request, new MemoryStream(Encoding.UTF8.GetBytes(value)), contentType);
    private static string Resource(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("EmbySso.Web." + name)
            ?? throw new InvalidOperationException("Missing embedded resource");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
    private static string Bounded(string? value, int maximum) => value != null && value.Length <= maximum
        ? value : throw new SsoException("请求参数无效。");
    private object Guard(Func<object> action)
    {
        try { return action(); }
        catch (Exception error) { return Failure(error); }
    }
    private async Task<object> GuardAsync(Func<Task<object>> action)
    {
        try { return await action(); }
        catch (Exception error) { return Failure(error); }
    }
    private object Failure(Exception error)
    {
        // Token libraries and remote HTTP exceptions can carry credentials. Log only the exception type.
        logger.Warn("SSO request failed: {0}", error.GetType().Name);
        Request.Response.StatusCode = 400;
        return Message(error is SsoException ? error.Message : "登录未完成，请重新开始或联系管理员检查 SSO 配置。",
            plugin.Configuration.Enabled ? plugin.Configuration : null);
    }
}
