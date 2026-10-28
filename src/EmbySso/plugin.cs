using System.Text;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Model.Logging;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace EmbySso;

public sealed class Plugin : BasePlugin<Configuration>, IHasWebPages, IServerEntryPoint
{
    private readonly IServerApplicationPaths serverPaths;
    private readonly ILogger logger;
    public static Plugin Instance { get; private set; } = null!;
    public override string Name => "Rauthy SSO";
    public override string Description => "通过 OpenID Connect 登录、创建和绑定 Emby 账号。";
    public override Guid Id => Guid.Parse("0f20ca35-3f79-4b49-8d12-8bc5924d5ad8");
    public BindingStore Bindings { get; }
    public TicketStore<string> Forms { get; } = new();
    public TicketStore<OidcFlow> Flows { get; } = new();
    public TicketStore<SessionTicket> Sessions { get; } = new();
    public LoginCodes LoginCodes { get; } = new();
    public RateLimiter Limiter { get; } = new();
    public OidcClient Oidc { get; }
    public Accounts? Accounts { get; set; }

    public Plugin(IApplicationPaths paths, IServerApplicationPaths serverPaths,
        IXmlSerializer serializer, ILogManager logs) : base(paths, serializer)
    {
        Instance = this;
        this.serverPaths = serverPaths;
        logger = logs.GetLogger("EmbySso");
        Bindings = new BindingStore(Path.Combine(paths.DataPath, "emby-sso", "bindings.json"));
        Oidc = new OidcClient(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(20), MaxResponseContentBufferSize = 262144
        });
    }

    public void Run()
    {
        try
        {
            InstallLoginButton(serverPaths.ApplicationResourcesPath);
        }
        catch (Exception error)
        {
            // A read-only installation must not stop the plugin from loading.
            logger.Warn("Unable to add the SSO button to the Emby login page: {0}", error.GetType().Name);
        }
    }

    public void Dispose() { }

    private static void InstallLoginButton(string resourcesPath)
    {
        if (string.IsNullOrEmpty(resourcesPath)) return;
        var file = Path.Combine(resourcesPath, "dashboard-ui", "index.html");
        if (!File.Exists(file)) return;
        var html = File.ReadAllText(file);
        if (html.Contains("sso/assets/entry.js", StringComparison.Ordinal)) return;
        var head = html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
        if (head < 0) return;
        html = html.Insert(head,
            "<script defer src=\"../sso/assets/entry.js\"></script><!-- EmbySso login button -->");
        File.WriteAllText(file, html, new UTF8Encoding(true));
    }

    public IEnumerable<PluginPageInfo> GetPages() =>
    [
        new() { Name = "rauthy-sso", EmbeddedResourcePath = "EmbySso.Web.configuration.html" },
        new() { Name = "rauthyssojs", EmbeddedResourcePath = "EmbySso.Web.configuration.js" }
    ];
}

public sealed record SessionTicket(string UserId, string ConfigurationFingerprint);
