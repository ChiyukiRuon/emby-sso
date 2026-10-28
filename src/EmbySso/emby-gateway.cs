using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Users;

namespace EmbySso;

public sealed class EmbyGateway(IUserManager users) : IAccountGateway
{
    public static Account Describe(User user) => new(user.Id.ToString("N"), user.Name);
    public Account? Find(string id)
    {
        var user = users.GetUserById(id);
        return user == null ? null : Describe(user);
    }
    public bool NameExists(string name) => users.GetUserByName(name) != null;
    public string ValidName(string name) => users.MakeValidUsername(name);
    public void AssertAllowed(Account account)
    {
        var user = users.GetUserById(account.Id) ?? throw new SsoException("账号不存在。");
        var policy = users.GetUserPolicy(user);
        if (policy.IsDisabled)
            throw new SsoException("此 Emby 账号已停用，不能使用 SSO。");
        if (!user.IsParentalScheduleAllowed())
            throw new SsoException("此 Emby 账号当前不在允许访问时段，不能使用 SSO。");
    }

    public async Task<Account> CreateDisabled(string name, string[] libraryIds)
    {
        var user = await users.CreateUser(name, NewUserPolicy(libraryIds));
        return Describe(user);
    }

    public static UserPolicy NewUserPolicy(string[] libraryIds) => new()
    {
        IsAdministrator = false, IsDisabled = true, IsHidden = true, IsHiddenRemotely = true,
        EnableAllFolders = false, EnabledFolders = libraryIds.ToArray(),
        EnableAllChannels = false, EnabledChannels = [], EnableLiveTvAccess = false,
        EnableLiveTvManagement = false, EnableContentDeletion = false,
        EnableContentDeletionFromFolders = [], EnableContentDownloading = false,
        EnableRemoteControlOfOtherUsers = false, EnableSharedDeviceControl = false,
        EnableRemoteAccess = true, EnableMediaPlayback = true, EnableAllDevices = true,
        EnableAudioPlaybackTranscoding = true, EnableVideoPlaybackTranscoding = true,
        EnablePlaybackRemuxing = true, EnableUserPreferenceAccess = true
    };

    public Task SetPassword(Account account, string password) => users.ChangePassword(users.GetUserById(account.Id), password);
    public string PasswordFingerprint(Account account) => Secrets.Hash(users.GetUserById(account.Id).Password ?? "");
    public void Enable(Account account)
    {
        var user = users.GetUserById(account.Id);
        var policy = users.GetUserPolicy(user);
        policy.IsDisabled = false;
        users.UpdateUserPolicy(user.InternalId, policy);
    }
    public Task Delete(Account account) => users.DeleteUser(users.GetUserById(account.Id));
}
