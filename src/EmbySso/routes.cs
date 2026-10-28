using MediaBrowser.Controller.Net;
using MediaBrowser.Model.Services;

namespace EmbySso;

[Route("/sso/password-status", "GET")]
public sealed class PasswordStatusRequest : IReturn<string>;

[Route("/sso", "GET"), Unauthenticated]
public sealed class PortalRequest : IReturn<string>;

[Route("/sso/assets/{Name}", "GET"), Unauthenticated]
public sealed class AssetRequest : IReturn<string>
{
    public string Name { get; set; } = "";
}

[Route("/sso/start", "POST"), Unauthenticated]
public sealed class StartRequest : IReturn<string>
{
    public string Csrf { get; set; } = "";
    public string Action { get; set; } = "login";
}

[Route("/sso/callback", "GET"), Unauthenticated]
public sealed class CallbackRequest : IReturn<string>
{
    public string State { get; set; } = "";
    public string Code { get; set; } = "";
    public string Error { get; set; } = "";
    public string Iss { get; set; } = "";
}

[Route("/sso/session", "POST"), Unauthenticated]
public sealed class SessionRequest : IReturn<object>
{
    public string Ticket { get; set; } = "";
}

[Route("/sso/profile", "GET")]
public sealed class ProfileRequest : IReturn<object>;

[Route("/sso/profile", "POST")]
public sealed class ProfileActionRequest : IReturn<object>
{
    public string Csrf { get; set; } = "";
    public string Action { get; set; } = "";
    public string Password { get; set; } = "";
}
