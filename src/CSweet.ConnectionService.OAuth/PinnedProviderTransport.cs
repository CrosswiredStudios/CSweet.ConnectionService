using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService;

public sealed record ProviderTokenReceipt(string AccessToken, string? RefreshToken, long ExpiresIn, string[]? Scopes)
{
    public override string ToString() => "Provider receipt [credentials redacted]";
}
public interface IProviderOAuthTransport
{
    Task<ProviderTokenReceipt> Exchange(ProviderProfile profile, string secret, string code, string verifier, string callback, CancellationToken ct);
    Task<ProviderTokenReceipt> Refresh(ProviderProfile profile, string secret, string refreshToken, CancellationToken ct) => throw new NotSupportedException();
    Task<bool> Revoke(ProviderProfile profile, string secret, string token, CancellationToken ct) => throw new NotSupportedException();
}
public interface IProviderApiTransport
{
    Task<JsonElement> Read(Uri destination, string accessToken, CancellationToken ct);
}

/// <summary>Only operator-reviewed token endpoints. Pinned public DNS, no proxies, cookies or redirects.</summary>
public sealed class PinnedProviderTransport : IProviderOAuthTransport, IProviderApiTransport
{
    public async Task<ProviderTokenReceipt> Exchange(ProviderProfile profile, string secret, string code, string verifier, string callback, CancellationToken ct)
    {
        var uri = Guards.Https(profile.TokenEndpoint);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(20));
        var addresses = await Dns.GetHostAddressesAsync(uri.DnsSafeHost, timeout.Token);
        if (addresses.Length == 0 || addresses.Any(IsForbidden)) throw new UnauthorizedAccessException();
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (_, cancel) =>
            {
                var socket = new Socket(addresses[0].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(new IPEndPoint(addresses[0], 443), cancel); return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            }
        };
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            { ["grant_type"] = "authorization_code", ["client_id"] = profile.ClientId, ["client_secret"] = secret, ["code"] = code, ["code_verifier"] = verifier, ["redirect_uri"] = callback })
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException("Provider authorization failed.");
        await using var input = await response.Content.ReadAsStreamAsync(timeout.Token); using var output = new MemoryStream(); var buffer = new byte[8192];
        while (true) { var count = await input.ReadAsync(buffer, timeout.Token); if (count == 0) break; if (output.Length + count > 65536) throw new InvalidOperationException("Provider response too large."); output.Write(buffer, 0, count); }
        using var json = JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 8 }); var root = json.RootElement;
        if (root.EnumerateObject().Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count()) throw new InvalidOperationException("Ambiguous token response.");
        var access = root.GetProperty("access_token").GetString()!; Guards.Text(access, 8192);
        if (!root.TryGetProperty("token_type", out var type) || !string.Equals(type.GetString(), "Bearer", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unsupported token type.");
        var refresh = root.TryGetProperty("refresh_token", out var r) ? r.GetString() : null;
        if (refresh is not null) Guards.Text(refresh, 8192);
        if (!root.TryGetProperty("expires_in", out var expiry) || !expiry.TryGetInt64(out var seconds) || seconds is < 1 or > 86400) throw new InvalidOperationException("Unsupported token lifetime.");
        var scopes = root.TryGetProperty("scope", out var s) ? (s.GetString() ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries) : null;
        if (scopes is not null && (scopes.Length > 100 || scopes.Any(x => x.Length > 2048 || x.Any(char.IsControl)))) throw new InvalidOperationException("Invalid granted permissions.");
        return new(access, refresh, seconds, scopes);
    }
    public async Task<JsonElement> Read(Uri destination, string accessToken, CancellationToken ct)
    {
        using var response = await Send(destination, null, accessToken, ct);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("Provider read failed.", null, response.StatusCode);
        return await ReadJson(response, 4 * 1024 * 1024, ct);
    }
    public async Task<ProviderTokenReceipt> Refresh(ProviderProfile profile, string secret, string refreshToken, CancellationToken ct)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "refresh_token", ["client_id"] = profile.ClientId, ["client_secret"] = secret, ["refresh_token"] = refreshToken });
        using var response = await Send(Guards.Https(profile.TokenEndpoint), content, null, ct);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("Provider refresh failed.", null, response.StatusCode);
        var root = await ReadJson(response, 65536, ct);
        if (!root.TryGetProperty("token_type", out var kind) || kind.GetString() is not { } type || !string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Unsupported token type.");
        var access = root.GetProperty("access_token").GetString()!; Guards.Text(access, 8192);
        var nextRefresh = root.TryGetProperty("refresh_token", out var next) ? next.GetString() : null;
        if (nextRefresh is not null) Guards.Text(nextRefresh, 8192);
        if (!root.TryGetProperty("expires_in", out var expiry) || !expiry.TryGetInt64(out var seconds) || seconds is < 1 or > 86400)
            throw new InvalidOperationException("Invalid token lifetime.");
        var scopes = root.TryGetProperty("scope", out var scope) ? scope.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries) : null;
        return new(access, nextRefresh, seconds, scopes);
    }
    public async Task<bool> Revoke(ProviderProfile profile, string secret, string token, CancellationToken ct)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        { ["token"] = token, ["client_id"] = profile.ClientId, ["client_secret"] = secret });
        using var response = await Send(Guards.Https(profile.RevocationEndpoint), content, null, ct);
        return response.IsSuccessStatusCode;
    }
    private static async Task<JsonElement> ReadJson(HttpResponseMessage response, int limit, CancellationToken ct)
    {
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream(); var buffer = new byte[8192];
        while (true) { var count = await input.ReadAsync(buffer, ct); if (count == 0) break; if (output.Length + count > limit) throw new InvalidOperationException("Provider response too large."); output.Write(buffer, 0, count); }
        using var doc = JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        RegistryService.CheckDuplicates(doc.RootElement); return doc.RootElement.Clone();
    }
    private static async Task<HttpResponseMessage> Send(Uri destination, HttpContent? content, string? bearer, CancellationToken ct)
    {
        _ = Guards.Https(destination.GetLeftPart(UriPartial.Path));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(25));
        var addresses = await Dns.GetHostAddressesAsync(destination.DnsSafeHost, timeout.Token);
        if (addresses.Length == 0 || addresses.Any(IsForbidden)) throw new UnauthorizedAccessException();
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (_, cancel) =>
            {
                var socket = new Socket(addresses[0].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(new IPEndPoint(addresses[0], 443), cancel); return new NetworkStream(socket, true); }
                catch { socket.Dispose(); throw; }
            }
        };
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var request = new HttpRequestMessage(content is null ? HttpMethod.Get : HttpMethod.Post, destination) { Content = content };
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        // Buffer within the pinned transport's timeout and size limit; no caller-owned unbounded stream.
        using var received = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        await using var stream = await received.Content.ReadAsStreamAsync(timeout.Token);
        using var bytes = new MemoryStream(); var buffer = new byte[8192];
        while (true) { var count = await stream.ReadAsync(buffer, timeout.Token); if (count == 0) break; if (bytes.Length + count > 4 * 1024 * 1024) throw new InvalidOperationException("Provider result too large."); bytes.Write(buffer, 0, count); }
        return new HttpResponseMessage(received.StatusCode) { Content = new ByteArrayContent(bytes.ToArray()) };
    }
    public static bool IsForbidden(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var b = address.GetAddressBytes();
        if (b.Length == 4) return b[0] is 0 or 10 or 127 || b[0] >= 224 || b[0] == 169 && b[1] == 254 || b[0] == 172 && b[1] is >= 16 and <= 31 ||
            b[0] == 192 && b[1] is 0 or 168 || b[0] == 100 && b[1] is >= 64 and <= 127 || b[0] == 198 && b[1] is 18 or 19;
        // Permit only globally routable unicast 2000::/3; excludes mapped, ULA, link local and transition ranges.
        return (b[0] & 0xe0) != 0x20 || b[0] == 0x20 && b[1] == 0x01 && (b[2] == 0 || b[2] == 0x0d && b[3] == 0xb8) || b[0] == 0x20 && b[1] == 0x02;
    }
}
