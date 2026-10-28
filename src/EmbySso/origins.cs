namespace EmbySso;

// Browsers omit default ports from Host and Origin headers. Compare normalized values so
// PublicUrl = https://emby.example.com:443 behaves the same as https://emby.example.com.
public static class Origins
{
    public static string Authority(string value)
    {
        var text = (value ?? "").Trim();
        if (text.Length == 0) return "";
        if (text[0] == '[')
        {
            var end = text.IndexOf(']');
            if (end < 0) return text;
            var rest = text[(end + 1)..];
            return rest is ":443" or ":80" ? text[..(end + 1)] : text;
        }
        var colon = text.LastIndexOf(':');
        if (colon > 0 && text.IndexOf(':') == colon && text[(colon + 1)..] is "443" or "80")
            return text[..colon];
        return text;
    }

    public static string Origin(string value, bool allowHttp = false)
    {
        if (!Uri.TryCreate((value ?? "").Trim(), UriKind.Absolute, out var uri))
            return "";
        if (uri.Scheme != Uri.UriSchemeHttps && !(allowHttp && uri.Scheme == Uri.UriSchemeHttp))
            return "";
        return uri.Scheme + "://" + Authority(uri.Authority);
    }

    public static string PublicAuthority(string url, bool allowHttp = false)
    {
        var origin = Origin(url, allowHttp);
        var separator = origin.IndexOf("://", StringComparison.Ordinal);
        return separator < 0 ? "" : origin[(separator + 3)..];
    }
}
