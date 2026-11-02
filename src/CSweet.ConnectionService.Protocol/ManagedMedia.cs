using System.Text.Json;
using System.Text.Json.Serialization;

namespace CSweet.ConnectionService.Protocol;

/// <summary>Core attests approved media provenance. The service does not independently prove a
/// human decision or reconstruct a complete asset checksum from separate chunk checksums.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ManagedMediaRequest(ManagedReadRequest Operation, string IdempotencyKey, Guid AssetId,
    string AssetSha256, long SizeBytes, string ContentType, string ApprovalReference, long ValidUntil)
{
    public override string ToString() => "Managed media plan [content redacted]";
    public string BindingHash(Guid connection) => DeploymentProofCodec.Hash(JsonSerializer.Serialize(
        new { connection, request = this with { Operation = Operation with { ExpiresAt = 0 } } }, DeploymentProofCodec.Json));
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ManagedMediaControl(string BindingHash);
public sealed record ManagedMediaResult(Guid TransferId, string BindingHash, string State, int StatusCode,
    long CommittedBytes, long Revision, JsonElement? Result = null, long? RetryAt = null)
{ public override string ToString() => "Managed media receipt [content redacted]"; }

public sealed partial class ManagedConnectionClient
{
    public Task<ManagedMediaResult> BeginMedia(Guid connection, ManagedMediaRequest request, CancellationToken ct = default) =>
        MediaResult(() => Send<ManagedMediaResult>(HttpMethod.Post, $"/v1/connections/{connection:D}/media", request, ct),
            request.BindingHash(connection), null);
    public Task<ManagedMediaResult> ProbeMedia(Guid transfer, string binding, CancellationToken ct = default) =>
        MediaResult(() => Send<ManagedMediaResult>(HttpMethod.Post, $"/v1/media/{transfer:D}/probe", new ManagedMediaControl(binding), ct), binding, transfer);
    public Task<ManagedMediaResult> CancelMedia(Guid transfer, string binding, CancellationToken ct = default) =>
        MediaResult(() => Send<ManagedMediaResult>(HttpMethod.Post, $"/v1/media/{transfer:D}/cancel", new ManagedMediaControl(binding), ct), binding, transfer);
    public Task<ManagedMediaResult> MediaChunk(Guid transfer, string binding, long offset, ReadOnlyMemory<byte> chunk, CancellationToken ct = default)
    {
        if (transfer == Guid.Empty || binding.Length != 64 || binding.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) || offset < 0 ||
            chunk.Length is < 1 or > ManagedExecutionProtocol.MaximumChunkBytes) throw new ArgumentException("Invalid media range.");
        return MediaResult(() => SendBytes<ManagedMediaResult>(HttpMethod.Post,
            $"/v1/media/{transfer:D}/chunks/{offset}/{binding}", chunk.ToArray(), "application/octet-stream", ct), binding, transfer);
    }
    private async Task<ManagedMediaResult> MediaResult(Func<Task<ManagedMediaResult>> send, string binding, Guid? transfer)
    {
        var result = await send();
        if (result.TransferId == Guid.Empty || transfer is { } id && result.TransferId != id || result.BindingHash != binding ||
            result.Revision < 1 || result.CommittedBytes is < 0 or > 256L * 1024 * 1024 * 1024 ||
            result.State is not ("Ready" or "ProbeRequired" or "Completed" or "Cancelled") ||
            result.StatusCode is not (0 or 200 or 201 or 308 or 429 or 500 or 502 or 503 or 504) ||
            result.State == "Completed" && (result.StatusCode is not (200 or 201) || result.Result is not { ValueKind: JsonValueKind.Object }) ||
            result.State != "Completed" && result.Result is not null ||
            result.RetryAt is { } retry && (retry < 0 || retry > clock.GetUtcNow().AddDays(1).ToUnixTimeSeconds()))
            throw new InvalidOperationException("The media receipt does not match its signed transfer.");
        return result;
    }
}
