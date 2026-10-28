using MediaBrowser.Common;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;

namespace EmbySso;

public sealed class CodeAuthenticationProvider(IApplicationHost appHost, IUserManager users)
    : IAuthenticationProvider, IRequiresResolvedUser
{
    public const string DefaultProviderId = "Emby.Server.Implementations.Library.DefaultAuthenticationProvider";
    public static string ProviderId => typeof(CodeAuthenticationProvider).FullName!;
    private readonly Lazy<IAuthenticationProvider> local = new(() =>
        appHost.GetExports<IAuthenticationProvider>().Single(p => p.GetType().FullName == DefaultProviderId));
    public string Name => "SSO login code + local password";
    // Keep local passwords available even when SSO is disabled.
    public bool IsEnabled => true;
    public Task<ProviderAuthenticationResult> Authenticate(string username, string password) =>
        Authenticate(username, password, users.GetUserByName(username));

    public async Task<ProviderAuthenticationResult> Authenticate(string username, string password, User resolvedUser)
    {
        if (resolvedUser == null) throw new UnauthorizedAccessException("Invalid credentials");
        var plugin = Plugin.Instance;
        var account = EmbyGateway.Describe(resolvedUser);
        new EmbyGateway(users).AssertAllowed(account);
        var config = plugin.Configuration;
        if (config.Enabled && password is { Length: 6 } && password.All(char.IsAsciiDigit))
        {
            try
            {
                plugin.Limiter.Check("login-code:" + account.Id, 10);
                var snapshot = config.Snapshot();
                if (users.GetUserPolicy(resolvedUser).EnableRemoteAccess
                    && plugin.Bindings.IsBound(snapshot.Issuer, account.Id)
                    && plugin.LoginCodes.Take(account.Id, password, snapshot.Fingerprint))
                    return new ProviderAuthenticationResult { Username = resolvedUser.Name, DisplayName = resolvedUser.Name };
            }
            catch (SsoException)
            {
                // Code throttling or invalid SSO configuration must not disable local passwords.
            }
        }
        return await AuthenticateLocal(username, password, resolvedUser);
    }

    public Task<ProviderAuthenticationResult> AuthenticateLocal(string username, string password, User user) =>
        local.Value is IRequiresResolvedUser resolved
            ? resolved.Authenticate(username, password, user)
            : local.Value.Authenticate(username, password);
    public Task ChangePassword(User user, string newPassword) => local.Value.ChangePassword(user, newPassword);
    public Task<bool> HasPassword(User user) => local.Value.HasPassword(user);
}
