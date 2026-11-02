using System.Text.Json;
using System.Text.Json.Serialization;

namespace CSweet.ConnectionService.Protocol;

public static class ManagedExecutionProtocol
{
    public const int MaximumInputBytes = 256 * 1024;
    public const int MaximumReadResultBytes = 768 * 1024;
    public const int MaximumChunkBytes = 8 * 1024 * 1024;
}

/// <summary>Core attests its grant/plan checks. The service separately verifies its own authorities.
/// Neither these identifiers nor the deployment signature prove a human approval by themselves.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ManagedReadRequest(string TenantId, Guid InstallationId, Guid RequesterInstallationId,
    string PackageDigest, string Capability, string ResourceId, JsonElement Input, string CorePlanHash, long ExpiresAt)
{ public override string ToString() => "Managed read [input redacted]"; }

public sealed record ManagedReadResult(Guid ConnectionId, long ConnectionRevision, string OperationHash, JsonElement Result)
{ public override string ToString() => "Managed read result [content redacted]"; }

public static class ManagedExecutionBinding
{
    public static string Hash(Guid connectionId, ManagedReadRequest request) =>
        DeploymentProofCodec.Hash(JsonSerializer.Serialize(new { connectionId, request }, DeploymentProofCodec.Json));
}

public sealed partial class ManagedConnectionClient
{
    public async Task<ManagedReadResult> ReadOperation(Guid connectionId, ManagedReadRequest request, CancellationToken ct = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(http.Timeout == Timeout.InfiniteTimeSpan || http.Timeout > TimeSpan.FromSeconds(30) ? TimeSpan.FromSeconds(30) : http.Timeout);
        var result = await Send<ManagedReadResult>(HttpMethod.Post, $"/v1/connections/{connectionId:D}/operations/read", request, deadline.Token);
        if (result.ConnectionId != connectionId || result.ConnectionRevision < 1 || result.OperationHash != ManagedExecutionBinding.Hash(connectionId, request))
            throw new InvalidOperationException("The relay response does not match its signed operation.");
        return result;
    }
}
