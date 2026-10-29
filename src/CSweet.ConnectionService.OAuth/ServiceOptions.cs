using System.Text.RegularExpressions;

namespace CSweet.ConnectionService;

public sealed class ServiceOptions
{
    public const string Section = "ConnectionService";
    public string PublicOrigin { get; set; } = "";
    public string Database { get; set; } = "";
    public string KeyRingDirectory { get; set; } = "";
    public string ProtectionCertificatePath { get; set; } = "";
    public string ProtectionCertificatePassword { get; set; } = "";
    public bool EnableOidcAdministration { get; set; }
    public string OperatorAuthority { get; set; } = "";
    public string OperatorAudience { get; set; } = "";
    public bool InitializeDevelopmentStore { get; set; }
    // Retained to fail closed for older configurations instead of silently accepting them.
    public bool AllowDevelopmentLoopbackReturns { get; set; }
    public string[] AllowedLocalBrowserReturnUris { get; set; } = [];
    public string[] KnownProxyAddresses { get; set; } = [];
    public string Callback(string profileId) => PublicOrigin + "/oauth/callback/" + Uri.EscapeDataString(profileId);
    public void Validate(bool development)
    {
        if (AllowDevelopmentLoopbackReturns) throw new InvalidOperationException("Replace AllowDevelopmentLoopbackReturns with exact HTTPS AllowedLocalBrowserReturnUris.");
        BrowserReturnPolicy.ValidateConfiguration(AllowedLocalBrowserReturnUris);
        var origin = Guards.Https(PublicOrigin);
        if (origin.AbsolutePath != "/" || PublicOrigin.EndsWith('/')) throw new InvalidOperationException("Configure an HTTPS service origin without a trailing slash.");
        if (string.IsNullOrWhiteSpace(Database) || string.IsNullOrWhiteSpace(KeyRingDirectory)) throw new InvalidOperationException("Configure persistent database and key-ring storage.");
        if (EnableOidcAdministration) { Guards.Https(OperatorAuthority); Guards.Text(OperatorAudience, 512); }
        if (!development && (InitializeDevelopmentStore || string.IsNullOrWhiteSpace(ProtectionCertificatePath)))
            throw new InvalidOperationException("Production requires encrypted durable keys and an explicitly initialized store.");
    }
    public void ValidateReturn(string target) => BrowserReturnPolicy.Validate(target, AllowedLocalBrowserReturnUris);
}
public static partial class Guards
{
    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex IdPattern();
    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)] private static partial Regex DigestPattern();
    public static void Text(string? value, int max) { if (string.IsNullOrWhiteSpace(value) || value.Length > max || value.Any(char.IsControl)) throw new ArgumentException("Invalid text field."); }
    public static void Id(string value) { if (!IdPattern().IsMatch(value)) throw new ArgumentException("Invalid identifier."); }
    public static void Digest(string value) { if (!DigestPattern().IsMatch(value)) throw new ArgumentException("Invalid digest."); }
    public static Uri Https(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || !uri.IsDefaultPort || uri.HostNameType != UriHostNameType.Dns ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || uri.Host.EndsWith('.') || uri.IsLoopback)
            throw new ArgumentException("An exact public HTTPS address is required.");
        return uri;
    }
}
