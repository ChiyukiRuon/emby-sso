// TEST ONLY. Never install this assembly on a real server.
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EmbySso;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Services;
using MediaBrowser.Model.Users;

namespace EmbySso.LiveHarness;

// The runner sets these so the same harness works with non-default test ports.
internal static class TestConfig
{
    public static readonly string Issuer = Environment.GetEnvironmentVariable("EMBY_SSO_ISSUER")
        ?? "https://auth.test/auth/v1/";
    public static readonly string PublicUrl = Environment.GetEnvironmentVariable("EMBY_SSO_PUBLIC_URL")
        ?? "https://localhost:18997";
}

[Route("/sso-test/setup", "POST"), Unauthenticated]
public sealed class SetupRequest : IReturn<object>;

public sealed class TestService(IUserManager users) : IService, IRequiresRequest
{
    static TestService()
    {
        System.Runtime.Loader.AssemblyLoadContext.GetLoadContext(typeof(TestService).Assembly)!.Resolving += (_, name) =>
            AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == name.Name);
    }
    public IRequest Request { get; set; } = null!;

    public async Task<object> Post(SetupRequest request)
    {
        var secret = Environment.GetEnvironmentVariable("EMBY_SSO_TEST_SECRET");
        if (string.IsNullOrEmpty(secret) || !Secrets.Equal(Request.Headers["X-Test-Secret"] ?? "", secret))
            throw new UnauthorizedAccessException();
        var plugin = Plugin.Instance;
        // Independent test phases must not share production rate-limit counters.
        typeof(Plugin).GetField("<Limiter>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(plugin, new RateLimiter());
        plugin.Configuration.Enabled = true;
        plugin.Configuration.AllowInsecureHttp =
            Environment.GetEnvironmentVariable("EMBY_SSO_ALLOW_INSECURE_HTTP") == "1";
        plugin.Configuration.PublicUrl = TestConfig.PublicUrl;
        plugin.Configuration.Issuer = TestConfig.Issuer;
        plugin.Configuration.ClientId = "emby-test";
        plugin.Configuration.ClientSecret = "test-secret";
        plugin.Configuration.AutoCreateUsers = true;
        plugin.SaveConfiguration();
        var existing = users.GetUserByName("existing-user") ?? await users.CreateUser("existing-user", new UserPolicy
        { IsAdministrator = false, EnableAllFolders = false, EnableRemoteAccess = true });
        await users.ChangePassword(existing, "ExistingPassword123!");
        var admin = users.GetUserByName("sso-admin") ?? await users.CreateUser("sso-admin", new UserPolicy
        { IsAdministrator = true, EnableAllFolders = true, EnableRemoteAccess = true, EnableAllDevices = true });
        await users.ChangePassword(admin, "SsoAdminPassword123!");
        typeof(Plugin).GetField("<Oidc>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(plugin, new OidcClient(new HttpClient(new TestProvider())));
        return new { Ready = true };
    }
}

sealed class TestProvider : HttpMessageHandler
{
    private readonly RSA rsa = RSA.Create(2048);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var issuer = TestConfig.Issuer;
        if (request.RequestUri!.AbsolutePath.EndsWith("openid-configuration"))
            return Json(new { issuer, authorization_endpoint = issuer + "authorize", token_endpoint = issuer + "token", jwks_uri = issuer + "certs" });
        if (request.RequestUri.AbsolutePath.EndsWith("certs"))
        {
            var key = rsa.ExportParameters(false);
            return Json(new { keys = new[] { new { kty = "RSA", kid = "test-key", alg = "RS256", use = "sig", n = Secrets.Base64Url(key.Modulus!), e = Secrets.Base64Url(key.Exponent!) } } });
        }
        var form = (await request.Content!.ReadAsStringAsync(cancellationToken)).Split('&')
            .Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));
        var code = form["code"].Split('|', 2);
        var header = Secrets.Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { alg = "RS256", kid = "test-key" })));
        var payload = Secrets.Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            iss = issuer, aud = "emby-test", sub = code[0], preferred_username = code[0], nonce = code[1],
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()
        })));
        var input = header + "." + payload;
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Json(new { id_token = input + "." + Secrets.Base64Url(signature) });
    }
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
    { Content = new StringContent(JsonSerializer.Serialize(value)) };
}
