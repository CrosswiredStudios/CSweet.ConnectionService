using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.OAuth.Google;

/// <summary>Google-specific export handling only. Consent, custody, HTTP and grants remain generic.</summary>
public sealed class GoogleOAuthCredentialDocumentReader : IOAuthCredentialDocumentReader
{
    public string Format => "google-web-client";
    public ConfigureProvider Read(string profileId, JsonElement document, string expectedCallback)
    {
        if (document.ValueKind != JsonValueKind.Object || document.EnumerateObject().GroupBy(x => x.Name, StringComparer.Ordinal).Any(x => x.Count() != 1) ||
            !document.TryGetProperty("web", out var web) || web.ValueKind != JsonValueKind.Object ||
            web.EnumerateObject().GroupBy(x => x.Name, StringComparer.Ordinal).Any(x => x.Count() != 1))
            throw new ArgumentException("A Google web-application export is required.");
        string Field(string name)
        {
            if (!web.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(value.GetString()) || value.GetString()!.Length > 4096 || value.GetString()!.Any(char.IsControl))
                throw new ArgumentException("The credential export is incomplete.");
            return value.GetString()!;
        }
        var authorization = Field("auth_uri");
        if (authorization is not ("https://accounts.google.com/o/oauth2/auth" or "https://accounts.google.com/o/oauth2/v2/auth") ||
            Field("token_uri") != "https://oauth2.googleapis.com/token" || !web.TryGetProperty("redirect_uris", out var redirects) ||
            redirects.ValueKind != JsonValueKind.Array || !redirects.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == expectedCallback))
            throw new ArgumentException("The Google export must register this service's exact callback.");
        return new(profileId, Field("client_id"), "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/revoke", Field("client_secret"))
        { RevocationGroup = Field("project_id") };
    }
}

public static class GoogleOAuthSupport
{
    public static IServiceCollection AddGoogleOAuthSupport(this IServiceCollection services) =>
        services.AddSingleton<IOAuthCredentialDocumentReader, GoogleOAuthCredentialDocumentReader>()
            .AddSingleton<IOAuthScopeConvention, GoogleOAuthScopeConvention>();
}

/// <summary>Google returns canonical API scope names for some OpenID scope aliases.</summary>
public sealed class GoogleOAuthScopeConvention : IOAuthScopeConvention
{
    public bool Matches(ProviderProfile profile) => profile.AuthorizationEndpoint == "https://accounts.google.com/o/oauth2/v2/auth" &&
        profile.TokenEndpoint == "https://oauth2.googleapis.com/token" && profile.RevocationEndpoint == "https://oauth2.googleapis.com/revoke";
    public string Canonical(string scope) => scope switch
    {
        "profile" => "https://www.googleapis.com/auth/userinfo.profile",
        "email" => "https://www.googleapis.com/auth/userinfo.email",
        _ => scope
    };
    public int AuthorizationOrder(string scope) => scope == "openid" ? -1 : 0;
}
