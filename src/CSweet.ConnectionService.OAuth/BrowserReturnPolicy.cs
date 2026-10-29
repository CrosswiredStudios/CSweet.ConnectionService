using System.Net;

namespace CSweet.ConnectionService;

// Browser navigation only. Never use this policy for service origins, provider URLs or outbound HTTP.
internal static class BrowserReturnPolicy
{
    public static void ValidateConfiguration(string[] localReturns)
    {
        if (localReturns is null || localReturns.Length > 20 || localReturns.Distinct(StringComparer.Ordinal).Count() != localReturns.Length)
            throw new ArgumentException("Choose at most twenty distinct exact local HTTPS browser returns.");
        foreach (var value in localReturns) _ = Local(value);
    }

    public static void Validate(string target, string[] localReturns)
    {
        ValidateConfiguration(localReturns);
        Guards.Text(target, 2048);
        if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && uri.IsLoopback)
        {
            _ = Local(target);
            if (!localReturns.Contains(target, StringComparer.Ordinal)) throw new ArgumentException("The local browser return is not explicitly allowed.");
            return;
        }
        // Preserve the existing public-return boundary. This does not widen any public/provider guard.
        _ = Guards.Https(target);
    }

    private static Uri Local(string value)
    {
        Guards.Text(value, 2048);
        if (value.Any(char.IsWhiteSpace) || value.IndexOfAny(['%', '\\', '?', '#']) >= 0 ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !uri.IsLoopback || uri.Port < 1 ||
            !(uri.Host == "localhost" || IPAddress.TryParse(uri.IdnHost, out var address) && IPAddress.IsLoopback(address)) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            !string.Equals(value, uri.AbsoluteUri, StringComparison.Ordinal))
            throw new ArgumentException("Configure an exact canonical local HTTPS browser return without credentials, query, fragment or encoding.");
        return uri;
    }
}
