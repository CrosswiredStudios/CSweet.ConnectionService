using Microsoft.AspNetCore.Http.Features;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService;

internal static class ManagedMediaRoutes
{
    internal const string BodyKey = "managed-media-chunk";
    internal static bool IsChunk(HttpRequest request)
    {
        var parts = request.Path.Value?.Split('/');
        return request.Method == "POST" && request.PathBase == "" && request.QueryString == QueryString.Empty &&
            parts is { Length: 7 } && parts[0] == "" && parts[1] == "v1" && parts[2] == "media" &&
            Guid.TryParseExact(parts[3], "D", out _) && parts[4] == "chunks" &&
            long.TryParse(parts[5], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var offset) && offset >= 0 &&
            parts[6].Length == 64 && parts[6].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
    internal static void SetLimit(HttpContext context)
    {
        if (!IsChunk(context.Request)) return;
        if (context.Request.ContentType != "application/octet-stream" || context.Request.ContentLength is not (> 0 and <= ManagedExecutionProtocol.MaximumChunkBytes))
            throw new BadHttpRequestException("Invalid bounded chunk.", 413);
        var feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (feature is { IsReadOnly: false }) feature.MaxRequestBodySize = ManagedExecutionProtocol.MaximumChunkBytes;
    }
}
