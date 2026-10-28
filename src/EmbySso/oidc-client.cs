using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace EmbySso;

public sealed record Identity(string Issuer, string Subject, string Username);
public sealed record OidcFlow(Configuration Configuration, string Nonce, string Verifier, string? LinkUserId, bool ClientCode = false);
public sealed record Discovery(string Issuer, string AuthorizationEndpoint, string TokenEndpoint, string JwksUri);

public sealed class OidcClient(HttpClient http)
{
    private readonly SemaphoreSlim metadataGate = new(1);
    private (string Issuer, DateTimeOffset Until, Discovery Discovery, IList<SecurityKey> Keys)? cache;

    public async Task<string> AuthorizationUrl(OidcFlow flow, string state, CancellationToken cancellationToken)
    {
        var metadata = await Metadata(flow.Configuration, false, cancellationToken);
        return metadata.Discovery.AuthorizationEndpoint + "?" + Query(new()
        {
            ["client_id"] = flow.Configuration.ClientId,
            ["redirect_uri"] = flow.Configuration.CallbackUrl,
            ["response_type"] = "code", ["response_mode"] = "query",
            ["scope"] = flow.Configuration.Scopes, ["state"] = state,
            ["nonce"] = flow.Nonce, ["code_challenge"] = Secrets.Hash(flow.Verifier),
            ["code_challenge_method"] = "S256",
            // Binding should visibly select an identity rather than silently using an existing IdP session.
            ["prompt"] = flow.LinkUserId == null ? "" : "login"
        });
    }

    public async Task<Identity> Exchange(OidcFlow flow, string code, CancellationToken cancellationToken)
    {
        var config = flow.Configuration;
        var metadata = await Metadata(config, false, cancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Post, metadata.Discovery.TokenEndpoint);
        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = config.CallbackUrl, ["client_id"] = config.ClientId,
            ["code_verifier"] = flow.Verifier
        };
        if (config.ClientAuthentication == "client_secret_basic")
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(
                Encoding.UTF8.GetBytes(FormEncode(config.ClientId) + ":" + FormEncode(config.ClientSecret))));
        else if (config.ClientAuthentication == "client_secret_post") fields["client_secret"] = config.ClientSecret;
        request.Content = new FormUrlEncodedContent(fields);
        using var response = await http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode) throw new SsoException("身份提供商拒绝了登录请求，请重新登录。");
        using var tokens = await ReadJson(response, cancellationToken);
        var idToken = RequiredString(tokens.RootElement, "id_token");
        try
        {
            return await Validate(idToken, config, flow.Nonce, metadata.Keys);
        }
        catch (SecurityTokenInvalidAlgorithmException)
        {
            throw new SsoException("ID Token 使用了不支持的签名算法，请将 Rauthy 客户端的 ID Token Algorithm 设置为 RS256、RS384 或 RS512。");
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            // One refresh supports signing-key rotation without trusting keys from the token itself.
            metadata = await Metadata(config, true, cancellationToken);
            try
            {
                return await Validate(idToken, config, flow.Nonce, metadata.Keys);
            }
            catch (SecurityTokenInvalidAlgorithmException)
            {
                throw new SsoException("ID Token 使用了不支持的签名算法，请将 Rauthy 客户端的 ID Token Algorithm 设置为 RS256、RS384 或 RS512。");
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                throw new SsoException("ID Token 的签名密钥不在 JWKS 中，请将 Rauthy 客户端的 ID Token Algorithm 设置为 RS256、RS384 或 RS512。");
            }
        }
    }

    public static async Task<Identity> Validate(string token, Configuration config, string nonce, IEnumerable<SecurityKey> keys)
    {
        var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = 32768, MapInboundClaims = false };
        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            RequireSignedTokens = true, ValidateIssuerSigningKey = true, IssuerSigningKeys = keys, TryAllIssuerSigningKeys = false,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512],
            ValidateIssuer = true, ValidIssuer = config.Issuer,
            ValidateAudience = true, ValidAudience = config.ClientId, RequireAudience = true,
            ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = TimeSpan.FromSeconds(30),
            // Do not normalize trailing slashes: Rauthy's issuer is an exact identity boundary.
            IgnoreTrailingSlashWhenValidatingAudience = false
        });
        if (!result.IsValid) throw result.Exception ?? new SecurityTokenException("Invalid ID token");
        var jwt = (JsonWebToken)result.SecurityToken;
        using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload));
        var root = payload.RootElement;
        var subject = RequiredString(root, "sub");
        if (subject.Length > 512 || !Secrets.Equal(RequiredString(root, "nonce"), nonce))
            throw new SsoException("登录令牌校验失败。");
        if (!root.TryGetProperty("iat", out var issued) || !issued.TryGetInt64(out var iat)
            || iat > DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds())
            throw new SsoException("登录令牌的签发时间无效。");
        var azp = root.TryGetProperty("azp", out var party) ? party.GetString() : null;
        if ((jwt.Audiences.Count() > 1 && azp == null) || (azp != null && azp != config.ClientId))
            throw new SsoException("登录令牌的授权客户端不匹配。");
        if (config.RequireVerifiedEmail && (!root.TryGetProperty("email_verified", out var verified)
            || verified.ValueKind != JsonValueKind.True))
            throw new SsoException("请先在身份提供商中验证邮箱。");
        if (config.RequiredClaim.Length > 0 && (!root.TryGetProperty(config.RequiredClaim, out var claim)
            || !Matches(claim, config.RequiredValue)))
            throw new SsoException("当前 SSO 账号没有访问此 Emby 的权限。");
        var username = root.TryGetProperty("preferred_username", out var name) && name.ValueKind == JsonValueKind.String
            ? name.GetString()! : "sso-" + Secrets.Hash(config.Issuer + "\n" + subject)[..16];
        return new Identity(config.Issuer, subject, username);
    }

    private static bool Matches(JsonElement claim, string required) => claim.ValueKind == JsonValueKind.String
        ? claim.GetString() == required
        : claim.ValueKind == JsonValueKind.Array && claim.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == required);

    private async Task<(Discovery Discovery, IList<SecurityKey> Keys)> Metadata(Configuration config, bool refresh, CancellationToken cancellationToken)
    {
        await metadataGate.WaitAsync(cancellationToken);
        try
        {
            if (!refresh && cache is { } current && current.Issuer == config.Issuer && current.Until > DateTimeOffset.UtcNow)
                return (current.Discovery, current.Keys);
            // Rauthy publishes discovery at the origin root although its issuer contains /auth/v1/.
            var discoveryUrl = config.DiscoveryUrl.Length > 0 ? config.DiscoveryUrl
                : new Uri(config.Issuer).GetLeftPart(UriPartial.Authority) + "/.well-known/openid-configuration";
            using var response = await http.GetAsync(discoveryUrl, cancellationToken);
            response.EnsureSuccessStatusCode();
            using var document = await ReadJson(response, cancellationToken);
            var root = document.RootElement;
            var discovery = new Discovery(RequiredString(root, "issuer"), RequiredString(root, "authorization_endpoint"),
                RequiredString(root, "token_endpoint"), RequiredString(root, "jwks_uri"));
            if (discovery.Issuer != config.Issuer) throw new SsoException("Issuer 与发现文档不一致，请检查末尾的斜杠。");
            foreach (var endpoint in new[] { discovery.AuthorizationEndpoint, discovery.TokenEndpoint, discovery.JwksUri })
            {
                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
                    || (uri.Scheme != Uri.UriSchemeHttps
                        && !(config.AllowInsecureHttp && uri.Scheme == Uri.UriSchemeHttp))
                    || uri.UserInfo != "" || uri.Fragment != "" || uri.Query != ""
                    || uri.GetLeftPart(UriPartial.Authority) != new Uri(config.Issuer).GetLeftPart(UriPartial.Authority))
                    throw new SsoException(config.AllowInsecureHttp
                        ? "OIDC 端点必须使用与 Issuer 相同来源的 HTTP(S) 地址。"
                        : "OIDC 端点必须使用与 Issuer 相同来源的 HTTPS 地址。");
            }
            using var keyResponse = await http.GetAsync(discovery.JwksUri, cancellationToken);
            keyResponse.EnsureSuccessStatusCode();
            using var keyDocument = await ReadJson(keyResponse, cancellationToken);
            var keySet = new JsonWebKeySet(keyDocument.RootElement.GetRawText());
            IList<SecurityKey> keys = keySet.Keys.Where(k => k.Kty == "RSA" && (k.Use is null or "" or "sig")
                && (k.Alg is null or "" or "RS256" or "RS384" or "RS512")).Cast<SecurityKey>().ToList();
            if (keys.Count == 0) throw new SsoException("未发现 RSA 签名密钥，请将 Rauthy 客户端的 ID Token Algorithm 设置为 RS256、RS384 或 RS512。");
            cache = (config.Issuer, DateTimeOffset.UtcNow.AddMinutes(5), discovery, keys);
            return (discovery, keys);
        }
        finally { metadataGate.Release(); }
    }

    private static async Task<JsonDocument> ReadJson(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (body.Length > 262144) throw new SsoException("OIDC 响应过大。");
        return JsonDocument.Parse(body);
    }

    private static string RequiredString(JsonElement value, string key) => value.TryGetProperty(key, out var field)
        && field.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(field.GetString())
        ? field.GetString()! : throw new SsoException("OIDC 响应缺少必要字段。");

    private static string FormEncode(string value) => Uri.EscapeDataString(value).Replace("%20", "+");
    private static string Query(Dictionary<string, string> values) => string.Join("&", values.Where(p => p.Value.Length > 0)
        .Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
}
