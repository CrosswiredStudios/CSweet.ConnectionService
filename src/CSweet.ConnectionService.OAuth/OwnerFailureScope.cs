using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

// Only fixed operation/stage/type labels enter diagnostics. Never log an exception object or message.
internal sealed class OwnerFailureScope
{
    private readonly long started = Stopwatch.GetTimestamp();
    private readonly string correlation = Guid.NewGuid().ToString("N");
    private string Operation { get; init; } = "unknown";
    public string Stage { get; private set; } = "transport";
    private static readonly object ItemKey = new();
    public static void Begin(HttpContext context)
    {
        var operation = context.Request.Path.Value switch {
            "/owner-control/v1/access" => "access", "/owner-control/v1/credentials/import" => "import",
            "/owner-control/v1/packages/approve" => "approve", "/owner-control/v1/deployments/enroll" => "enroll",
            "/owner-control/v1/deployments/revoke" => "revoke", _ => null
        };
        if (operation is not null) context.Items[ItemKey] = new OwnerFailureScope { Operation = operation };
    }
    public static void SetStage(HttpContext context, string stage)
    { if (context.Items.TryGetValue(ItemKey, out var value) && value is OwnerFailureScope scope) scope.Stage = stage; }
    public static void Report(HttpContext context, Exception? error)
    {
        if (!context.Items.TryGetValue(ItemKey, out var value) || value is not OwnerFailureScope scope) return;
        var status = (HttpStatusCode)context.Response.StatusCode;
        var stage = status == HttpStatusCode.Forbidden ? "authorization" : scope.Stage;
        var type = error switch {
            null => "none", UnauthorizedAccessException => "UnauthorizedAccessException", CryptographicException => "CryptographicException",
            DbUpdateException => "DbUpdateException", JsonException => "JsonException", FormatException => "FormatException",
            BadHttpRequestException => "BadHttpRequestException", ArgumentException => "ArgumentException", InvalidOperationException => "InvalidOperationException", _ => "Exception"
        };
        var diagnostic = new OwnerFailureDiagnostic(stage, OwnerFailureDiagnostic.CodeFor(status), type, scope.correlation,
            (int)Math.Min(OwnerFailureDiagnostic.MaximumElapsedMilliseconds, Stopwatch.GetElapsedTime(scope.started).TotalMilliseconds));
        context.Response.Headers[OwnerFailureDiagnostic.Header] = diagnostic.Encode(status);
        context.RequestServices.GetRequiredService<ILogger<OwnerControl>>().LogWarning(
            "Owner control rejected: operation={Operation} stage={Stage} code={Code} status={Status} exceptionType={ExceptionType} correlationId={CorrelationId} elapsedMs={ElapsedMilliseconds}",
            scope.Operation, diagnostic.Stage, diagnostic.Code, (int)status, diagnostic.ExceptionType, diagnostic.CorrelationId, diagnostic.ElapsedMilliseconds);
    }
}
