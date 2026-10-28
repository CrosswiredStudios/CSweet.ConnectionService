using System.Security.Cryptography;
using System.Text.Json;

namespace CSweet.ConnectionService.Protocol;

/// <summary>Host backchannel client. No provider client secret or provider token API.</summary>
public sealed class ManagedConnectionClient(HttpClient http, Uri serviceUri, Guid deploymentId, string keyId, long deploymentRevision, ECDsa deploymentKey, TimeProvider clock)
{
    public Task<ProfileAvailability> Availability(string digest, CancellationToken ct = default) => Send<ProfileAvailability>(HttpMethod.Get, "/v1/packages/" + Uri.EscapeDataString(digest), null, ct);
    public Task<DeploymentRegistration> Registration(CancellationToken ct = default) => Send<DeploymentRegistration>(HttpMethod.Get, "/v1/deployment", null, ct);
    public Task<ConnectionAttempt> Begin(BeginConnection request, CancellationToken ct = default) => Send<ConnectionAttempt>(HttpMethod.Post, "/v1/sessions", request, ct);
    public Task<ConnectionReceipt> Cancel(Guid id, CancellationToken ct = default) => Send<ConnectionReceipt>(HttpMethod.Post, $"/v1/sessions/{id:D}/cancel", new { }, ct);
    public Task<ConnectionReceipt> CancelAttempt(Guid localAttemptId, CancellationToken ct = default) => Send<ConnectionReceipt>(HttpMethod.Post, $"/v1/attempts/{localAttemptId:D}/cancel", new { }, ct);
    public Task<ConnectionSnapshot> Supersede(Guid previous, Guid replacement, CancellationToken ct = default) => Send<ConnectionSnapshot>(HttpMethod.Post, $"/v1/connections/{previous:D}/supersede/{replacement:D}", new { }, ct);
    public Task<ConnectionReceipt> Redeem(RedeemConnection request, CancellationToken ct = default) => Send<ConnectionReceipt>(HttpMethod.Post, "/v1/handoffs/redeem", request, ct);
    public Task<ConnectionReceipt> Recover(Guid session, RecoverConnection request, CancellationToken ct = default) => Send<ConnectionReceipt>(HttpMethod.Post, $"/v1/sessions/{session:D}/receipt", request, ct);
    public Task<ConnectionSnapshot> Get(Guid id, CancellationToken ct = default) => Send<ConnectionSnapshot>(HttpMethod.Get, $"/v1/connections/{id:D}", null, ct);
    public Task<ConnectionInventory> Discover(Guid id, CancellationToken ct = default) => Send<ConnectionInventory>(HttpMethod.Post, $"/v1/connections/{id:D}/inventory", new { }, ct);
    public Task<ConnectionSnapshot> Disconnect(Guid id, CancellationToken ct = default) => Send<ConnectionSnapshot>(HttpMethod.Post, $"/v1/connections/{id:D}/disconnect", new { }, ct);
    public Task<IReadOnlyList<ServiceEvent>> Events(long after, CancellationToken ct = default) => Send<IReadOnlyList<ServiceEvent>>(HttpMethod.Get, $"/v1/events?after={after}", null, ct);
    private async Task<T> Send<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        if (!serviceUri.IsAbsoluteUri || serviceUri.Scheme != "https" || serviceUri.AbsolutePath != "/" || !string.IsNullOrEmpty(serviceUri.UserInfo) || !string.IsNullOrEmpty(serviceUri.Query) || !string.IsNullOrEmpty(serviceUri.Fragment)) throw new InvalidOperationException("An exact HTTPS service origin is required.");
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, DeploymentProofCodec.Json);
        if (bytes.Length > ConnectionProtocol.MaximumBodyBytes) throw new ArgumentException("Request exceeds the protocol limit.");
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        var proof = new DeploymentProof(deploymentId, keyId, serviceUri.AbsoluteUri.TrimEnd('/'), method.Method, path, DeploymentProofCodec.Hash(bytes), now, now + 30, DeploymentProofCodec.Random(), deploymentRevision);
        using var request = new HttpRequestMessage(method, new Uri(serviceUri, path));
        lock (deploymentKey) request.Headers.Add(ConnectionProtocol.ProofHeader, DeploymentProofCodec.Sign(proof, deploymentKey));
        if (body is not null) { request.Content = new ByteArrayContent(bytes); request.Content.Headers.ContentType = new("application/json"); }
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("The managed connection request was not accepted.", null, response.StatusCode);
        if (!response.Headers.TryGetValues("X-CSweet-Connection-Protocol", out var versions) || !versions.SequenceEqual([ConnectionProtocol.Version]))
            throw new InvalidOperationException("Unsupported managed connection protocol.");
        await using var input = await response.Content.ReadAsStreamAsync(ct); using var output = new MemoryStream(); var buffer = new byte[8192];
        while (true) { var count = await input.ReadAsync(buffer, ct); if (count == 0) break; if (output.Length + count > ConnectionProtocol.MaximumBodyBytes) throw new InvalidOperationException("Service result too large."); output.Write(buffer, 0, count); }
        return JsonSerializer.Deserialize<T>(output.ToArray(), DeploymentProofCodec.Json) ?? throw new InvalidOperationException("Empty service result.");
    }
}
