using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed class DeploymentAuthenticator(ConnectionStore db, ServiceOptions options, TimeProvider clock)
{
    public async Task<Deployment> Authenticate(HttpContext context, CancellationToken ct)
    {
        if (context.Request.ContentLength > ConnectionProtocol.MaximumBodyBytes) throw new BadHttpRequestException("Request too large.", 413);
        var header = context.Request.Headers[ConnectionProtocol.ProofHeader];
        if (header.Count != 1 || header[0] is not { Length: <= 8192 } encoded) throw new UnauthorizedAccessException();
        var segments = encoded.Split('.'); if (segments.Length != 2) throw new UnauthorizedAccessException();
        DeploymentProof unverified;
        try { unverified = JsonSerializer.Deserialize<DeploymentProof>(DeploymentProofCodec.Decode(segments[0]), DeploymentProofCodec.Json)!; }
        catch (Exception e) when (e is JsonException or FormatException) { throw new UnauthorizedAccessException(); }
        if (unverified is null) throw new UnauthorizedAccessException();
        var deployment = await db.Deployments.AsNoTracking().SingleOrDefaultAsync(x => x.Id == unverified.DeploymentId && !x.Revoked, ct) ?? throw new UnauthorizedAccessException();
        DeploymentProof proof;
        try { using var key = DeploymentProofCodec.PublicKey(deployment.PublicKey); proof = DeploymentProofCodec.Verify(encoded, key); }
        catch (Exception e) when (e is CryptographicException or FormatException or JsonException or ArgumentException) { throw new UnauthorizedAccessException(); }
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (proof.KeyId != deployment.KeyId || proof.DeploymentRevision != deployment.Revision || proof.Audience != options.PublicOrigin ||
            proof.Method != context.Request.Method || proof.PathAndQuery != context.Request.PathBase + context.Request.Path + context.Request.QueryString ||
            proof.IssuedAt > now + 5 || proof.IssuedAt < now - 30 || proof.ExpiresAt <= now || proof.ExpiresAt > proof.IssuedAt + 30 || proof.ExpiresAt <= proof.IssuedAt ||
            proof.Nonce is not { Length: >= 43 and <= 64 }) throw new UnauthorizedAccessException();
        context.Request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: ConnectionProtocol.MaximumBodyBytes);
        using var body = new MemoryStream(); var buffer = new byte[8192];
        while (true) { var read = await context.Request.Body.ReadAsync(buffer, ct); if (read == 0) break; if (body.Length + read > ConnectionProtocol.MaximumBodyBytes) throw new BadHttpRequestException("Request too large.", 413); body.Write(buffer, 0, read); }
        context.Request.Body.Position = 0;
        if (!DeploymentProofCodec.Equal(DeploymentProofCodec.Hash(body.ToArray()), proof.BodySha256)) throw new UnauthorizedAccessException();
        if (body.Length > 0)
        {
            using var document = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 64 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new ArgumentException("An object request is required.");
            RegistryService.CheckDuplicates(document.RootElement);
        }
        db.Nonces.Add(new() { DeploymentId = deployment.Id, NonceHash = DeploymentProofCodec.Hash(proof.Nonce), ExpiresAt = proof.ExpiresAt });
        try { await db.SaveChangesAsync(ct); } catch (DbUpdateException) { throw new UnauthorizedAccessException(); }
        return deployment;
    }
}
