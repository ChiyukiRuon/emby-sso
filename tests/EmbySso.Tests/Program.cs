using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using EmbySso;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var tests = new List<(string Name, Func<Task> Run)>();
void Test(string name, Action run) => tests.Add((name, () => { run(); return Task.CompletedTask; }));
void AsyncTest(string name, Func<Task> run) => tests.Add((name, run));
void Assert(bool value) { if (!value) throw new Exception("Assertion failed"); }
async Task Reject(Func<Task> run)
{
    try { await run(); } catch { return; }
    throw new Exception("Expected rejection");
}
void RejectSync(Action run)
{
    try { run(); } catch { return; }
    throw new Exception("Expected rejection");
}
var config = new Configuration { Enabled = true, PublicUrl = "https://emby.test/media", Issuer = "https://auth.test/auth/v1/", ClientId = "emby", ClientSecret = "test-secret" };
using var rsa = RSA.Create(2048);
var key = new RsaSecurityKey(rsa) { KeyId = "key-1" };
string Token(Dictionary<string, object>? changes = null, SecurityKey? signingKey = null, string algorithm = "RS256")
{
    var claims = new Dictionary<string, object>
    {
        ["iss"] = config.Issuer, ["aud"] = config.ClientId, ["sub"] = "person-1", ["nonce"] = "nonce",
        ["preferred_username"] = "alice", ["email_verified"] = true, ["roles"] = new[] { "emby", "other" },
        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        ["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-20).ToUnixTimeSeconds()
    };
    if (changes != null) foreach (var item in changes) claims[item.Key] = item.Value;
    return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    { Claims = claims, SigningCredentials = new SigningCredentials(signingKey ?? key, algorithm) });
}
Test("login codes are account bound, single use and replaced on reissue", () =>
{
    var codes = new LoginCodes();
    var first = codes.Issue("alice", "config");
    Assert(first.Length == 6 && first.All(char.IsAsciiDigit));
    Assert(!codes.Take("bob", first, "config"));
    Assert(!codes.Take("alice", "bad", "config"));
    var second = codes.Issue("alice", "config");
    Assert(!codes.Take("alice", first, "config"));
    Assert(codes.Take("alice", second, "config"));
    Assert(!codes.Take("alice", second, "config"));
});
Test("revoked login codes cannot be redeemed", () =>
{
    var codes = new LoginCodes();
    var code = codes.Issue("alice", "config");
    codes.Revoke("alice");
    Assert(!codes.Take("alice", code, "config"));
});
Test("login codes expire and configuration changes invalidate them", () =>
{
    var clock = new TestClock();
    var codes = new LoginCodes(clock);
    var code = codes.Issue("alice", "old");
    Assert(!codes.Take("alice", code, "new"));
    Assert(!codes.Take("alice", code, "old"));
    code = codes.Issue("alice", "old");
    clock.Advance(TimeSpan.FromMinutes(5));
    Assert(!codes.Take("alice", code, "old"));
});
AsyncTest("concurrent login code redemption succeeds only once", async () =>
{
    var codes = new LoginCodes();
    var code = codes.Issue("alice", "config");
    var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() => codes.Take("alice", code, "config"))));
    Assert(results.Count(success => success) == 1);
});
Test("PKCE S256 RFC 7636 vector", () => Assert(Secrets.Hash("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
Test("exact issuer and subpath survive config snapshot", () =>
{
    var copy = config.Snapshot(); Assert(copy.Issuer == config.Issuer && copy.Fingerprint == config.Fingerprint);
    Assert(copy.CallbackUrl == "https://emby.test/media/sso/callback");
});
Test("invalid config rejected", () =>
{
    var c = config.Snapshot(); c.Issuer = "http://auth.test"; RejectSync(c.Validate);
    c = config.Snapshot(); c.ClientSecret = ""; RejectSync(c.Validate);
    c = config.Snapshot(); c.RequiredClaim = "roles"; RejectSync(c.Validate);
    c = config.Snapshot(); c.Enabled = false; RejectSync(c.Validate);
});
Test("insecure http requires the explicit switch", () =>
{
    var c = config.Snapshot(); c.PublicUrl = "http://emby.test"; RejectSync(c.Validate);
    c = config.Snapshot(); c.Issuer = "http://auth.test/auth/v1/"; RejectSync(c.Validate);
    c = config.Snapshot(); c.AllowInsecureHttp = true; c.PublicUrl = "http://emby.test"; c.Issuer = "http://auth.test/auth/v1/";
    c.Validate(); Assert(c.CallbackUrl == "http://emby.test/sso/callback");
    c.DiscoveryUrl = "http://auth.test/.well-known/openid-configuration"; c.Validate();
    var changed = config.Snapshot(); changed.AllowInsecureHttp = true;
    Assert(changed.Fingerprint != config.Fingerprint);
});
Test("tickets resist cross-browser consumption and replay", () =>
{
    var tickets = new TicketStore<int>(); var token = tickets.Add("browser-1", 42);
    RejectSync(() => tickets.Take(token, "browser-2")); Assert(tickets.Take(token, "browser-1") == 42);
    RejectSync(() => tickets.Take(token, "browser-1")); RejectSync(() => tickets.Take("fake", "browser-1"));
});
Test("expired tickets rejected", () =>
{
    var clock = new TestClock(); var tickets = new TicketStore<int>(clock); var token = tickets.Add("browser", 1);
    clock.Advance(TimeSpan.FromMinutes(6)); RejectSync(() => tickets.Take(token, "browser"));
});
Test("rate limit windows expire", () =>
{
    var clock = new TestClock(); var limiter = new RateLimiter(clock);
    for (var i = 0; i < 20; i++) limiter.Check("ip");
    RejectSync(() => limiter.Check("ip")); limiter.Check("other"); clock.Advance(TimeSpan.FromMinutes(5)); limiter.Check("ip");
});
Test("ticket store stays available at capacity", () =>
{
    var tickets = new TicketStore<int>();
    for (var i = 0; i < 2048; i++) tickets.Add("browser", i);
    var token = tickets.Add("browser", 2048);
    Assert(tickets.Take(token, "browser") == 2048);
});
Test("rate limiter stays available at capacity", () =>
{
    var limiter = new RateLimiter();
    for (var i = 0; i < 4096; i++) limiter.Check("key-" + i);
    limiter.Check("key-new");
});
Test("public origin ignores default ports and gates insecure http", () =>
{
    Assert(Origins.Origin("https://emby.test:443/media") == "https://emby.test");
    Assert(Origins.PublicAuthority("https://emby.test:443/media") == "emby.test");
    Assert(Origins.Authority("emby.test:443") == "emby.test");
    Assert(Origins.Origin("https://emby.test:8443/media") == "https://emby.test:8443");
    Assert(Origins.Authority("[::1]:443") == "[::1]");
    Assert(Origins.Origin("http://emby.test") == "");
    Assert(Origins.Origin("http://emby.test", true) == "http://emby.test");
    Assert(Origins.PublicAuthority("http://emby.test:80/media", true) == "emby.test");
    Assert(Origins.Authority("emby.test:80") == "emby.test");
    Assert(Origins.Origin("http://emby.test:8080", true) == "http://emby.test:8080");
});
AsyncTest("valid RSA ID token maps identity", async () => Assert(await OidcClient.Validate(Token(), config, "nonce", [key]) == new Identity(config.Issuer, "person-1", "alice")));
AsyncTest("RSA SHA-384 and SHA-512 ID tokens are accepted", async () =>
{
    Assert((await OidcClient.Validate(Token(algorithm: "RS384"), config, "nonce", [key])).Subject == "person-1");
    Assert((await OidcClient.Validate(Token(algorithm: "RS512"), config, "nonce", [key])).Subject == "person-1");
});
foreach (var change in new Dictionary<string, object>[]
{
    new() { ["iss"] = "https://evil.test/" }, new() { ["iss"] = config.Issuer.TrimEnd('/') },
    new() { ["aud"] = "other" }, new() { ["nonce"] = "wrong" }, new() { ["sub"] = "" },
    new() { ["exp"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds() },
    new() { ["iat"] = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds() },
    new() { ["azp"] = "other" }, new() { ["aud"] = new[] { "emby", "other" } }
})
{
    var mutation = change;
    AsyncTest("invalid token " + string.Join(",", change.Keys), () => Reject(async () => await OidcClient.Validate(Token(mutation), config, "nonce", [key])));
}
AsyncTest("untrusted signing key rejected", async () =>
{
    using var attacker = RSA.Create(2048);
    await Reject(async () => await OidcClient.Validate(Token(signingKey: new RsaSecurityKey(attacker)), config, "nonce", [key]));
});
AsyncTest("symmetric algorithm confusion rejected", async () =>
{
    var symmetric = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
    await Reject(async () => await OidcClient.Validate(Token(signingKey: symmetric, algorithm: "HS256"), config, "nonce", [symmetric]));
});
AsyncTest("group and email rules enforced", async () =>
{
    var c = config.Snapshot(); c.RequiredClaim = "roles"; c.RequiredValue = "emby"; c.RequireVerifiedEmail = true;
    await OidcClient.Validate(Token(), c, "nonce", [key]);
    await Reject(async () => await OidcClient.Validate(Token(new() { ["roles"] = new[] { "other" } }), c, "nonce", [key]));
    await Reject(async () => await OidcClient.Validate(Token(new() { ["email_verified"] = false }), c, "nonce", [key]));
    await Reject(async () => await OidcClient.Validate(Token(new() { ["email_verified"] = "true" }), c, "nonce", [key]));
});
AsyncTest("discovery, PKCE, exchange and key rotation", async () =>
{
    var parameters = rsa.ExportParameters(false); var jwksCalls = 0;
    using var http = new HttpClient(new FakeHttp(async request =>
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("openid-configuration"))
            return Json(new { issuer = config.Issuer, authorization_endpoint = config.Issuer + "authorize", token_endpoint = config.Issuer + "token", jwks_uri = config.Issuer + "certs" });
        if (request.RequestUri.AbsolutePath.EndsWith("certs"))
        {
            jwksCalls++;
            return Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = jwksCalls == 1 ? "old-key" : "key-1", n = Secrets.Base64Url(parameters.Modulus!), e = Secrets.Base64Url(parameters.Exponent!) } } });
        }
        Assert(request.Method == HttpMethod.Post && request.Headers.Authorization?.Scheme == "Basic");
        var body = await request.Content!.ReadAsStringAsync();
        Assert(body.Contains("code_verifier=verifier") && body.Contains("grant_type=authorization_code"));
        return Json(new { id_token = Token() });
    }));
    var client = new OidcClient(http); var flow = new OidcFlow(config, "nonce", "verifier", null);
    var url = await client.AuthorizationUrl(flow, "state", default);
    Assert(url.Contains("code_challenge=" + Secrets.Hash("verifier")) && url.Contains("state=state"));
    Assert((await client.Exchange(flow, "code", default)).Subject == "person-1"); Assert(jwksCalls == 2);
});
AsyncTest("discovery issuer mismatch rejected", async () =>
{
    using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(Json(new
    { issuer = "https://evil.test/", authorization_endpoint = "https://evil.test/a", token_endpoint = "https://evil.test/t", jwks_uri = "https://evil.test/j" }))));
    await Reject(async () => await new OidcClient(http).AuthorizationUrl(new(config, "n", "v", null), "state", default));
});
AsyncTest("http OIDC endpoints require the insecure switch", async () =>
{
    var insecure = config.Snapshot();
    insecure.AllowInsecureHttp = true;
    insecure.PublicUrl = "http://emby.test";
    insecure.Issuer = "http://auth.test/auth/v1/";
    var parameters = rsa.ExportParameters(false);
    using var http = new HttpClient(new FakeHttp(request => Task.FromResult(
        request.RequestUri!.AbsolutePath.EndsWith("certs")
            ? Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "key-1",
                n = Secrets.Base64Url(parameters.Modulus!), e = Secrets.Base64Url(parameters.Exponent!) } } })
            : Json(new { issuer = insecure.Issuer, authorization_endpoint = insecure.Issuer + "authorize",
                token_endpoint = insecure.Issuer + "token", jwks_uri = insecure.Issuer + "certs" }))));
    var url = await new OidcClient(http).AuthorizationUrl(new(insecure, "n", "v", null), "state", default);
    Assert(url.StartsWith(insecure.Issuer + "authorize?"));
    var blocked = config.Snapshot();
    blocked.PublicUrl = "http://emby.test";
    blocked.Issuer = "http://auth.test/auth/v1/";
    await Reject(async () => await new OidcClient(http).AuthorizationUrl(new(blocked, "n", "v", null), "state", default));
});

var directory = Path.Combine(Path.GetTempPath(), "emby-sso-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
BindingStore Store() => new(Path.Combine(directory, Guid.NewGuid() + ".json"));
Test("bindings persist and reject takeover", () =>
{
    var path = Path.Combine(directory, "persist.json"); var store = new BindingStore(path);
    store.Bind(config.Issuer, "sub", "user-1"); store.Bind(config.Issuer, "sub", "user-1");
    RejectSync(() => store.Bind(config.Issuer, "sub", "user-2")); RejectSync(() => store.Bind(config.Issuer, "other", "user-1"));
    Assert(new BindingStore(path).Find(config.Issuer, "sub")!.UserId == "user-1");
    Assert(store.Find("https://another.test/", "sub") == null);
    store.Unbind(config.Issuer, "user-1"); Assert(new BindingStore(path).Find(config.Issuer, "sub") == null);
});
Test("corrupt binding database fails closed", () =>
{
    var path = Path.Combine(directory, "corrupt.json"); File.WriteAllText(path, "broken");
    RejectSync(() => new BindingStore(path)); Assert(File.ReadAllText(path) == "broken");
});
Test("password reminder persists until the actual password changes", () =>
{
    var path = Path.Combine(directory, "password-reminder.json");
    var store = new BindingStore(path);
    store.Bind(config.Issuer, "new", "new-user", "initial-fingerprint");
    store.Bind(config.Issuer, "existing", "existing-user");
    Assert(store.RequiresPasswordChange("new-user", "initial-fingerprint"));
    store = new BindingStore(path);
    Assert(store.RequiresPasswordChange("new-user", "initial-fingerprint"));
    Assert(!store.RequiresPasswordChange("existing-user", "other-fingerprint"));
    Assert(!store.RequiresPasswordChange("unknown", "initial-fingerprint"));
    Assert(!store.RequiresPasswordChange("new-user", "changed-fingerprint"));
    Assert(!new BindingStore(path).RequiresPasswordChange("new-user", "initial-fingerprint"));
});
Test("legacy bindings do not prompt existing users", () =>
{
    var path = Path.Combine(directory, "legacy-bindings.json");
    File.WriteAllText(path, JsonSerializer.Serialize(new[] { new { Issuer = config.Issuer,
        Subject = "legacy", UserId = "legacy-user", CreatedAt = DateTimeOffset.UtcNow } }));
    Assert(!new BindingStore(path).RequiresPasswordChange("legacy-user", "fingerprint"));
});
AsyncTest("parallel signups create one account", async () =>
{
    var gateway = new FakeAccounts(); var store = Store(); var accounts = new Accounts(gateway, store);
    var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => accounts.Resolve(new(config.Issuer, "sub", "alice"), null, config)));
    Assert(results.All(r => r.Id == results[0].Id) && gateway.Created == 1);
    Assert(gateway.Passwords[results[0].Id].Length == 43 && gateway.Enabled.Contains(results[0].Id));
    Assert(store.RequiresPasswordChange(results[0].Id, gateway.PasswordFingerprint(results[0])));
});
AsyncTest("name collision never auto-binds", async () =>
{
    var gateway = new FakeAccounts(); gateway.Add("existing", "alice"); var store = Store();
    await Reject(async () => await new Accounts(gateway, store).Resolve(new(config.Issuer, "sub", "alice"), null, config));
    Assert(store.Find(config.Issuer, "sub") == null && gateway.Created == 0);
});
AsyncTest("explicit binding preserves account and local password", async () =>
{
    var gateway = new FakeAccounts(); gateway.Add("existing", "local-name"); var store = Store(); var accounts = new Accounts(gateway, store);
    var linked = await accounts.Resolve(new(config.Issuer, "sub", "sso-name"), "existing", config);
    var login = await accounts.Resolve(new(config.Issuer, "sub", "renamed"), null, config);
    Assert(linked.Id == "existing" && login.Name == "local-name" && gateway.Created == 0 && gateway.Passwords.Count == 0);
    await accounts.Unbind(config.Issuer, linked); Assert(store.Find(config.Issuer, "sub") == null);
});
AsyncTest("disabled and deleted users cannot login or recreate", async () =>
{
    var gateway = new FakeAccounts(); gateway.Add("existing", "alice"); var store = Store(); store.Bind(config.Issuer, "sub", "existing");
    var accounts = new Accounts(gateway, store); gateway.Enabled.Clear();
    await Reject(async () => await accounts.Resolve(new(config.Issuer, "sub", "alice"), null, config));
    gateway.Users.Clear(); await Reject(async () => await accounts.Resolve(new(config.Issuer, "sub", "alice"), null, config));
    Assert(gateway.Created == 0);
});
AsyncTest("registration switch still allows explicit linking", async () =>
{
    var c = config.Snapshot(); c.AutoCreateUsers = false;
    var gateway = new FakeAccounts(); gateway.Add("existing", "alice"); var accounts = new Accounts(gateway, Store());
    await Reject(async () => await accounts.Resolve(new(config.Issuer, "sub", "new-name"), null, c));
    await accounts.Resolve(new(config.Issuer, "sub", "new-name"), "existing", c);
});
AsyncTest("failed provisioning removes only newly created disabled account", async () =>
{
    var gateway = new FakeAccounts { FailPassword = true }; gateway.Add("existing", "local"); var store = Store();
    await Reject(async () => await new Accounts(gateway, store).Resolve(new(config.Issuer, "sub", "alice"), null, config));
    Assert(gateway.Users.Count == 1 && gateway.Users.ContainsKey("existing") && store.Find(config.Issuer, "sub") == null);
});
AsyncTest("failed enable rolls back the new account and binding", async () =>
{
    var gateway = new FakeAccounts { FailEnable = true }; var store = Store();
    await Reject(async () => await new Accounts(gateway, store).Resolve(new(config.Issuer, "sub", "alice"), null, config));
    Assert(gateway.Users.Count == 0 && store.Find(config.Issuer, "sub") == null && gateway.Created == 1);
});
Test("new account permissions start restricted and disabled", () =>
{
    var policy = EmbyGateway.NewUserPolicy(["library-1"]);
    Assert(policy.IsDisabled && !policy.IsAdministrator && !policy.EnableAllFolders && policy.EnabledFolders.SequenceEqual(["library-1"]));
    Assert(!policy.EnableContentDeletion && !policy.EnableContentDownloading && !policy.EnableLiveTvManagement);
    Assert(!policy.EnableRemoteControlOfOtherUsers && !policy.EnableSharedDeviceControl);
});
var failed = 0;
try
{
    foreach (var test in tests)
    {
        try { await test.Run(); Console.WriteLine("PASS " + test.Name); }
        catch (Exception error) { failed++; Console.WriteLine("FAIL " + test.Name + "\n" + error); }
    }
}
finally { Directory.Delete(directory, true); }
Console.WriteLine($"{tests.Count - failed}/{tests.Count} passed");
return failed == 0 ? 0 : 1;

static HttpResponseMessage Json(object data) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(data)) };

sealed class FakeHttp(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => handler(request);
}
sealed class TestClock : TimeProvider
{
    private DateTimeOffset now = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => now;
    public void Advance(TimeSpan duration) => now += duration;
}
sealed class FakeAccounts : IAccountGateway
{
    public Dictionary<string, Account> Users { get; } = [];
    public HashSet<string> Enabled { get; } = [];
    public Dictionary<string, string> Passwords { get; } = [];
    public int Created { get; private set; }
    public bool FailPassword { get; set; }
    public bool FailEnable { get; set; }
    public void Add(string id, string name) { Users[id] = new(id, name); Enabled.Add(id); }
    public Account? Find(string id) => Users.GetValueOrDefault(id);
    public bool NameExists(string name) => Users.Values.Any(u => u.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    public string ValidName(string name) => name;
    public void AssertAllowed(Account account) { if (!Enabled.Contains(account.Id)) throw new SsoException("disabled"); }
    public Task<Account> CreateDisabled(string name, string[] libraryIds)
    {
        Created++; var account = new Account(Guid.NewGuid().ToString("N"), name); Users.Add(account.Id, account);
        return Task.FromResult(account);
    }
    public Task SetPassword(Account account, string password)
    {
        if (FailPassword) throw new IOException("test failure");
        Passwords.Add(account.Id, password); return Task.CompletedTask;
    }
    public string PasswordFingerprint(Account account) => Secrets.Hash(Passwords.GetValueOrDefault(account.Id, ""));
    public void Enable(Account account)
    {
        if (FailEnable) throw new SsoException("enable failed");
        Enabled.Add(account.Id);
    }
    public Task Delete(Account account) { Users.Remove(account.Id); return Task.CompletedTask; }
}
