using System.Net;
using System.Net.Http.Headers;

namespace CSweet.ConnectionService.Protocol;

/// <summary>Bounded, content-free hints. Remote hints never establish authority or retry safety.</summary>
public sealed record OwnerFailureDiagnostic(string Stage, string Code, string ExceptionType, string CorrelationId, int ElapsedMilliseconds)
{
    public const string Header = "X-CSweet-Owner-Diagnostic";
    public const int MaximumElapsedMilliseconds = 3600000;
    private static readonly string[] Stages = ["transport", "authorization", "envelope", "payload", "tenant", "key-id", "name", "public-key", "return", "enrollment", "operation", "persistence"];
    private static readonly string[] Types = ["none", "ArgumentException", "InvalidOperationException", "JsonException", "FormatException", "UnauthorizedAccessException", "CryptographicException", "DbUpdateException", "BadHttpRequestException", "HttpRequestException", "OperationCanceledException", "IOException", "Exception"];
    public static string CodeFor(HttpStatusCode status) => (int)status switch { 400 => "request_rejected", 403 => "not_authorized", 409 => "state_changed", _ => "request_failed" };
    public string Encode(HttpStatusCode status)
    {
        var value = $"v1.{Stage}.{Code}.{ExceptionType}.{CorrelationId}.{ElapsedMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)}";
        return Parse(value, status) is not null ? value : throw new ArgumentException("Invalid owner diagnostic.");
    }
    public static OwnerFailureDiagnostic? Read(HttpResponseHeaders headers, HttpStatusCode status)
    {
        if (!headers.TryGetValues(Header, out var values)) return null;
        using var iterator = values.GetEnumerator();
        if (!iterator.MoveNext()) return null;
        var value = iterator.Current;
        return iterator.MoveNext() ? null : Parse(value, status);
    }
    private static OwnerFailureDiagnostic? Parse(string value, HttpStatusCode status)
    {
        if (value.Length > 180 || (int)status is < 400 or > 599) return null;
        var parts = value.Split('.');
        if (parts.Length != 6 || parts[0] != "v1" || !Stages.Contains(parts[1], StringComparer.Ordinal) || parts[2] != CodeFor(status) || !Types.Contains(parts[3], StringComparer.Ordinal) ||
            parts[4].Length != 32 || parts[4].Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !int.TryParse(parts[5], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var elapsed) || elapsed is < 0 or > MaximumElapsedMilliseconds ||
            parts[5] != elapsed.ToString(System.Globalization.CultureInfo.InvariantCulture)) return null;
        // Never expose detailed stages before authorization, even if a remote service supplies them.
        if ((int)status == 403 && (parts[1] != "authorization" || parts[3] != "UnauthorizedAccessException")) return null;
        return new(parts[1], parts[2], parts[3], parts[4], elapsed);
    }
}

public sealed class OwnerOperationException(HttpStatusCode status, OwnerFailureDiagnostic? diagnostic)
    : HttpRequestException("Owner operation not accepted; check state before retrying.", null, status)
{
    public OwnerFailureDiagnostic? Diagnostic { get; } = diagnostic;
}
