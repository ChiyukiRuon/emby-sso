using System.Security.Cryptography;
using System.Text;

namespace EmbySso;

public static class Secrets
{
    public static string Random() => Base64Url(RandomNumberGenerator.GetBytes(32));
    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string Hash(string value) => Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static bool Equal(string a, string b) => CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(Encoding.UTF8.GetBytes(a)), SHA256.HashData(Encoding.UTF8.GetBytes(b)));
}

// Bounded, expiring, single-use capabilities. A wrong browser cannot consume another browser's ticket.
public sealed class TicketStore<T>(TimeProvider? time = null)
{
    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly Dictionary<string, (string Browser, DateTimeOffset Expiry, T Value)> entries = [];
    private readonly object gate = new();

    public string Add(string browser, T value, TimeSpan? lifetime = null)
    {
        lock (gate)
        {
            foreach (var key in entries.Where(p => p.Value.Expiry <= clock.GetUtcNow()).Select(p => p.Key).ToArray())
                entries.Remove(key);
            // Evict the ticket closest to expiry instead of failing every browser once the cap is reached.
            if (entries.Count >= 2048) entries.Remove(entries.MinBy(p => p.Value.Expiry).Key);
            var token = Secrets.Random();
            entries.Add(Secrets.Hash(token), (Secrets.Hash(browser), clock.GetUtcNow() + (lifetime ?? TimeSpan.FromMinutes(5)), value));
            return token;
        }
    }

    public T Take(string token, string browser)
    {
        lock (gate)
        {
            var key = Secrets.Hash(token);
            if (!entries.TryGetValue(key, out var entry) || entry.Expiry <= clock.GetUtcNow()
                || !Secrets.Equal(entry.Browser, Secrets.Hash(browser)))
                throw new SsoException("此操作已过期或不属于当前浏览器，请重新开始。");
            entries.Remove(key);
            return entry.Value;
        }
    }
}

public sealed class RateLimiter(TimeProvider? time = null)
{
    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly Dictionary<string, (DateTimeOffset Start, int Count)> entries = [];
    private readonly object gate = new();

    public void Check(string key, int limit = 20)
    {
        lock (gate)
        {
            var now = clock.GetUtcNow();
            foreach (var expired in entries.Where(p => now - p.Value.Start >= TimeSpan.FromMinutes(5)).Select(p => p.Key).ToArray())
                entries.Remove(expired);
            if (!entries.TryGetValue(key, out var item))
            {
                // Evict the oldest counter rather than letting a full table reject every request.
                if (entries.Count >= 4096) entries.Remove(entries.MinBy(p => p.Value.Start).Key);
                item = (now, 0);
            }
            if (item.Count >= limit) throw new SsoException("操作过于频繁，请五分钟后重试。");
            entries[key] = (item.Start, item.Count + 1);
        }
    }
}
