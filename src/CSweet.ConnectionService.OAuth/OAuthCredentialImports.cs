using System.Text.Json;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService;

/// <summary>Trusted adapters understand provider export formats; they do not override connector grants.</summary>
public interface IOAuthCredentialDocumentReader
{
    string Format { get; }
    ConfigureProvider Read(string profileId, JsonElement document, string expectedCallback);
}

public sealed record ImportOAuthCredentials(string ProfileId, JsonElement Document)
{
    public override string ToString() => "OAuth credentials import [redacted]";
}

public static class OAuthCredentialImports
{
    public static void MapOAuthCredentialImports(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/operator/credential-imports/{format}", async (string format, ImportOAuthCredentials request,
            HttpContext context, RegistryService registry, ServiceOptions options, IEnumerable<IOAuthCredentialDocumentReader> readers,
            CancellationToken ct) =>
        {
            var reader = readers.SingleOrDefault(x => x.Format == format) ?? throw new ArgumentException("Unsupported credential format.");
            var configuration = reader.Read(request.ProfileId, request.Document, options.Callback(request.ProfileId));
            return Results.Ok(await registry.Configure(context.User.FindFirst("sub")!.Value, configuration, ct));
        }).RequireAuthorization("operator").RequireRateLimiting("bounded");
    }
}
