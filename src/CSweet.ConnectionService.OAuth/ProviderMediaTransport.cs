using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace CSweet.ConnectionService;

public sealed record ProviderMediaRequest(Uri Destination, bool Begin, bool Probe, byte[] Body,
    string ContentType, long SizeBytes, long Offset)
{ public override string ToString() => "Provider media exchange [destination and content redacted]"; }
public sealed record ProviderMediaResponse(int StatusCode, string? SessionLocation, long? CommittedBytes,
    JsonElement? Result, long? RetryAt)
{ public override string ToString() => "Provider media response [session and content redacted]"; }
public interface IProviderMediaTransport
{
    Task<ProviderMediaResponse> Exchange(ProviderMediaRequest request, string accessToken, CancellationToken ct);
}

public sealed partial class PinnedProviderTransport : IProviderMediaTransport
{
    public async Task<ProviderMediaResponse> Exchange(ProviderMediaRequest exchange, string accessToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(exchange.Begin ? HttpMethod.Post : HttpMethod.Put, exchange.Destination)
            { Content = new ByteArrayContent(exchange.Body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content.Headers.ContentType = new(exchange.Begin ? "application/json" : exchange.ContentType);
        if (exchange.Begin)
        {
            request.Headers.Add("X-Upload-Content-Length", exchange.SizeBytes.ToString(CultureInfo.InvariantCulture));
            request.Headers.Add("X-Upload-Content-Type", exchange.ContentType);
        }
        else request.Content.Headers.ContentRange = exchange.Probe ? new ContentRangeHeaderValue(exchange.SizeBytes)
            : new ContentRangeHeaderValue(exchange.Offset, exchange.Offset + exchange.Body.Length - 1, exchange.SizeBytes);
        using var response = await SendRequest(request, ct);
        var code = (int)response.StatusCode; long? retry = null;
        if (response.Headers.TryGetValues("Retry-After", out var delays))
        {
            var values = delays.Take(2).ToArray();
            if (values.Length != 1 || !RetryConditionHeaderValue.TryParse(values[0], out var parsed)) throw new InvalidOperationException("Invalid provider retry bound.");
            var next = parsed.Date ?? DateTimeOffset.UtcNow.Add(parsed.Delta ?? TimeSpan.Zero);
            if (next > DateTimeOffset.UtcNow.AddDays(1)) throw new InvalidOperationException("Provider retry needs manual review.");
            retry = Math.Max(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), next.ToUnixTimeSeconds());
        }
        if (exchange.Begin && code is 200 or 201)
        {
            var locations = response.Headers.TryGetValues("Location", out var all) ? all.Take(2).ToArray() : [];
            if (locations.Length != 1) throw new InvalidOperationException("A single upload session is required.");
            return new(code, locations[0], null, null, retry);
        }
        if (!exchange.Begin && code == 308)
        {
            var ranges = response.Headers.TryGetValues("Range", out var all) ? all.Take(2).ToArray() : [];
            if (ranges.Length == 0) return new(code, null, 0, null, retry);
            if (ranges.Length != 1 || !ranges[0].StartsWith("bytes=0-", StringComparison.Ordinal) ||
                !long.TryParse(ranges[0].AsSpan(8), NumberStyles.None, CultureInfo.InvariantCulture, out var end) || end < 0 || end >= exchange.SizeBytes)
                throw new InvalidOperationException("Invalid provider upload range.");
            return new(code, null, end + 1, null, retry);
        }
        // Provider error bodies and redirect destinations never leave this transport.
        return new(code, null, null, !exchange.Begin && code is 200 or 201 ? await ReadJson(response, 768 * 1024, ct) : null, retry);
    }
}
