using System.Security.Cryptography;

namespace EmbySso;

// One active capability per account. Plaintext codes never persist.
public sealed class LoginCodes(TimeProvider? time = null)
{
    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly object gate = new();
    private readonly Dictionary<string, (string Hash, string Context, DateTimeOffset Expires)> entries = [];
    public string Issue(string userId, string context)
    {
        lock (gate)
        {
            foreach (var key in entries.Where(p => p.Value.Expires <= clock.GetUtcNow()).Select(p => p.Key).ToArray())
                entries.Remove(key);
            if (entries.Count >= 2048 && !entries.ContainsKey(userId))
                throw new SsoException("登录码请求过多，请稍后重试。");
            string code;
            do
            {
                code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
            }
            while (entries.TryGetValue(userId, out var previous) && Secrets.Equal(previous.Hash, Secrets.Hash(code)));
            entries[userId] = (Secrets.Hash(code), context, clock.GetUtcNow().AddMinutes(5));
            return code;
        }
    }
    public void Revoke(string userId)
    {
        lock (gate) entries.Remove(userId);
    }
    public bool Take(string userId, string code, string context)
    {
        lock (gate)
        {
            if (!entries.TryGetValue(userId, out var entry)) return false;
            if (entry.Expires <= clock.GetUtcNow() || entry.Context != context)
            {
                entries.Remove(userId);
                return false;
            }
            if (!Secrets.Equal(entry.Hash, Secrets.Hash(code))) return false;
            entries.Remove(userId);
            return true;
        }
    }
}
