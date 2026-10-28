using MediaBrowser.Model.Plugins;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EmbySso;

public sealed class Configuration : BasePluginConfiguration
{
    public bool Enabled { get; set; }
    public bool AllowInsecureHttp { get; set; }
    public string PublicUrl { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string DiscoveryUrl { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string ClientAuthentication { get; set; } = "client_secret_basic";
    public bool AutoCreateUsers { get; set; } = true;
    public bool RequireVerifiedEmail { get; set; }
    public string RequiredClaim { get; set; } = "";
    public string RequiredValue { get; set; } = "";
    public string[] NewUserLibraryIds { get; set; } = [];
    public string Scopes { get; set; } = "openid profile email";

    public string CallbackUrl => PublicUrl.TrimEnd('/') + "/sso/callback";
    public string Fingerprint => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        JsonSerializer.Serialize(new { Enabled, AllowInsecureHttp, PublicUrl, Issuer, DiscoveryUrl, ClientId, ClientSecret,
            ClientAuthentication, AutoCreateUsers, RequireVerifiedEmail, RequiredClaim,
            RequiredValue, NewUserLibraryIds, Scopes }))));

    public Configuration Snapshot()
    {
        var copy = JsonSerializer.Deserialize<Configuration>(JsonSerializer.Serialize(this))!;
        copy.Validate();
        return copy;
    }

    public void Validate()
    {
        if (!Enabled) throw new SsoException("SSO 尚未启用，请联系管理员。");
        foreach (var value in new[] { PublicUrl, Issuer })
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !AllowedScheme(uri)
                || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "")
                throw new SsoException(AllowInsecureHttp
                    ? "SSO 地址必须是完整的 HTTP(S) 地址，且不含查询参数。"
                    : "SSO 地址必须是完整的 HTTPS 地址，且不含查询参数。");
        }
        if (string.IsNullOrWhiteSpace(ClientId) || ClientId.Length > 256)
            throw new SsoException("请配置 OIDC Client ID。");
        if (DiscoveryUrl.Length > 0 && (!Uri.TryCreate(DiscoveryUrl, UriKind.Absolute, out var discovery)
            || !AllowedScheme(discovery) || discovery.UserInfo != "" || discovery.Query != "" || discovery.Fragment != ""
            || discovery.GetLeftPart(UriPartial.Authority) != new Uri(Issuer).GetLeftPart(UriPartial.Authority)))
            throw new SsoException(AllowInsecureHttp
                ? "发现文档必须是与 Issuer 相同来源的 HTTP(S) 地址。"
                : "发现文档必须是与 Issuer 相同来源的 HTTPS 地址。");
        if (ClientAuthentication is not ("client_secret_basic" or "client_secret_post" or "none"))
            throw new SsoException("不支持此客户端认证方式。");
        if (ClientAuthentication != "none" && string.IsNullOrWhiteSpace(ClientSecret))
            throw new SsoException("请配置 OIDC Client Secret。");
        if (!Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("openid"))
            throw new SsoException("Scope 必须包含 openid。");
        if (string.IsNullOrEmpty(RequiredClaim) != string.IsNullOrEmpty(RequiredValue))
            throw new SsoException("访问限制的声明名称和允许值必须同时配置。");
    }

    private bool AllowedScheme(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps || (AllowInsecureHttp && uri.Scheme == Uri.UriSchemeHttp);
}

public sealed class SsoException(string message) : Exception(message);
