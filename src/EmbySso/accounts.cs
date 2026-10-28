namespace EmbySso;

public sealed record Account(string Id, string Name);

public interface IAccountGateway
{
    Account? Find(string id);
    bool NameExists(string name);
    string ValidName(string name);
    void AssertAllowed(Account account);
    Task<Account> CreateDisabled(string name, string[] libraryIds);
    Task SetPassword(Account account, string password);
    string PasswordFingerprint(Account account);
    void Enable(Account account);
    Task Delete(Account account);
}

public sealed class Accounts(IAccountGateway gateway, BindingStore store)
{
    private readonly SemaphoreSlim gate = new(1);

    public async Task<Account> Resolve(Identity identity, string? linkUserId, Configuration config)
    {
        await gate.WaitAsync();
        try
        {
            var binding = store.Find(identity.Issuer, identity.Subject);
            if (linkUserId != null)
            {
                var target = gateway.Find(linkUserId) ?? throw new SsoException("待绑定的 Emby 账号已不存在。");
                gateway.AssertAllowed(target);
                store.Bind(identity.Issuer, identity.Subject, target.Id);
                return target;
            }
            if (binding != null)
            {
                // A deleted user is not automatically recreated or remapped to another same-name user.
                var user = gateway.Find(binding.UserId) ?? throw new SsoException("绑定的 Emby 账号已不存在，请联系管理员。");
                gateway.AssertAllowed(user);
                return user;
            }
            if (!config.AutoCreateUsers) throw new SsoException("尚未绑定 Emby 账号，请先使用现有账号绑定 SSO。");
            var name = gateway.ValidName(identity.Username.Trim());
            if (name.Length is < 1 or > 64) throw new SsoException("SSO 用户名无效，请在身份提供商设置用户名。");
            if (gateway.NameExists(name)) throw new SsoException("该用户名已存在。请先使用原账号登录 Emby，再到个人配置页面验证本地密码并绑定 SSO。");
            // A disabled account cannot be claimed through an empty-password login during provisioning.
            var created = await gateway.CreateDisabled(name, config.NewUserLibraryIds);
            try
            {
                await gateway.SetPassword(created, Secrets.Random());
                store.Bind(identity.Issuer, identity.Subject, created.Id, gateway.PasswordFingerprint(created));
                gateway.Enable(created);
                gateway.AssertAllowed(created);
                return created;
            }
            catch
            {
                // Keep the identity store and the new account consistent if any step after creation fails.
                try { store.Unbind(identity.Issuer, created.Id); } catch { }
                try { await gateway.Delete(created); } catch { }
                throw;
            }
        }
        finally { gate.Release(); }
    }

    public async Task Unbind(string issuer, Account account)
    {
        await gate.WaitAsync();
        try
        {
            gateway.AssertAllowed(account);
            store.Unbind(issuer, account.Id);
        }
        finally { gate.Release(); }
    }
}
