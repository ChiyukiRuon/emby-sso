using System.Text.Json;

namespace EmbySso;

public sealed record Binding(string Issuer, string Subject, string UserId, DateTimeOffset CreatedAt,
    string? InitialPasswordFingerprint = null);

public sealed class BindingStore
{
    private readonly string path;
    private readonly object gate = new();
    private List<Binding> bindings;

    public BindingStore(string path)
    {
        this.path = path;
        // Corruption fails closed; never replace an unreadable identity database with an empty one.
        bindings = File.Exists(path)
            ? JsonSerializer.Deserialize<List<Binding>>(File.ReadAllText(path)) ?? throw new InvalidDataException("Invalid SSO bindings")
            : [];
        if (bindings.Any(b => string.IsNullOrEmpty(b.Subject) || string.IsNullOrEmpty(b.Issuer) || string.IsNullOrEmpty(b.UserId))
            || bindings.GroupBy(b => (b.Issuer, b.Subject)).Any(g => g.Count() > 1)
            || bindings.GroupBy(b => (b.Issuer, b.UserId)).Any(g => g.Count() > 1))
            throw new InvalidDataException("Duplicate or invalid SSO bindings");
    }

    public Binding? Find(string issuer, string subject)
    {
        lock (gate) return bindings.SingleOrDefault(b => b.Issuer == issuer && b.Subject == subject);
    }

    public bool IsBound(string issuer, string userId)
    {
        lock (gate) return bindings.Any(b => b.Issuer == issuer && b.UserId == userId);
    }

    public bool RequiresPasswordChange(string userId, string passwordFingerprint)
    {
        lock (gate)
        {
            var pending = bindings.Where(b => b.UserId == userId && b.InitialPasswordFingerprint != null).ToList();
            if (pending.Count == 0) return false;
            if (pending.Any(b => b.InitialPasswordFingerprint == passwordFingerprint)) return true;
            Save(bindings.Select(b => b.UserId == userId ? b with { InitialPasswordFingerprint = null } : b).ToList());
            return false;
        }
    }

    public void Bind(string issuer, string subject, string userId, string? initialPasswordFingerprint = null)
    {
        lock (gate)
        {
            var existing = bindings.SingleOrDefault(b => b.Issuer == issuer && b.Subject == subject);
            if (existing?.UserId == userId) return;
            if (existing != null || bindings.Any(b => b.Issuer == issuer && b.UserId == userId))
                throw new SsoException("此 SSO 身份或 Emby 账号已有绑定，请先解除原绑定。");
            Save([.. bindings, new(issuer, subject, userId, DateTimeOffset.UtcNow, initialPasswordFingerprint)]);
        }
    }

    public void Unbind(string issuer, string userId)
    {
        lock (gate) Save(bindings.Where(b => b.Issuer != issuer || b.UserId != userId).ToList());
    }

    private void Save(List<Binding> updated)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, updated);
            stream.Flush(true);
        }
        File.Move(temporary, path, true);
        bindings = updated;
    }
}
