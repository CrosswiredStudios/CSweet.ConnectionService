using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed class OwnerBinding
{
    public Guid Id { get; set; }
    public string ServiceOrigin { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string KeyId { get; set; } = "";
    public long Revision { get; set; } = 1;
    public bool Revoked { get; set; }
}
public sealed class OwnerGrant
{
    public Guid BindingId { get; set; }
    public Guid ActorId { get; set; }
    public string TenantScope { get; set; } = "";
    public string CapabilitiesJson { get; set; } = "[]";
    public long Revision { get; set; } = 1;
    public bool Revoked { get; set; }
}
public sealed class OwnerNonce
{
    public Guid BindingId { get; set; }
    public string NonceHash { get; set; } = "";
    public long ExpiresAt { get; set; }
}
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record LocalOwnerCommand(string Action, string ServiceOrigin, Guid BindingId, string? PublicKey, string? KeyId,
    Guid ActorId, string? TenantScope, string[]? Capabilities, long ExpectedRevision)
{
    public static LocalOwnerCommand Parse(byte[] utf8)
    {
        if (utf8.Length > 65536) throw new ArgumentException("Command exceeds limit.");
        using var document = JsonDocument.Parse(utf8);
        RegistryService.CheckDuplicates(document.RootElement);
        return document.RootElement.Deserialize<LocalOwnerCommand>(DeploymentProofCodec.Json) ?? throw new ArgumentException("Missing command.");
    }
}

/// <summary>Local OS authority is required to read the protected service configuration/database. Never exposed as an HTTP endpoint.</summary>
public sealed class LocalOwnerAdministration(ConnectionStore db, ServiceOptions options, TimeProvider clock)
{
    public async Task<object> Execute(LocalOwnerCommand command, CancellationToken ct)
    {
        if (command.ServiceOrigin != options.PublicOrigin || command.BindingId == Guid.Empty) throw new ArgumentException("Review exact service and binding identity.");
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var binding = await db.OwnerBindings.SingleOrDefaultAsync(x => x.Id == command.BindingId, ct);
        var actor = "local-os:" + Environment.UserName;
        object result;
        if (command.Action == "bootstrap")
        {
            if (binding is not null || command.ExpectedRevision != 0 || command.PublicKey is null || command.KeyId is null) throw new InvalidOperationException("Use a fresh binding identity; never overwrite owner trust.");
            Guards.Id(command.KeyId); using var key = DeploymentProofCodec.PublicKey(command.PublicKey);
            if ((await db.Deployments.Select(x => x.PublicKey).ToListAsync(ct)).Concat(await db.OwnerBindings.Select(x => x.PublicKey).ToListAsync(ct)).Any(x => OwnerKeyIdentity.Same(x, command.PublicKey))) throw new InvalidOperationException("A separate new administrative key is required.");
            binding = new() { Id = command.BindingId, ServiceOrigin = options.PublicOrigin, PublicKey = command.PublicKey, KeyId = command.KeyId };
            db.OwnerBindings.Add(binding);
            AddGrant(command);
            result = new OwnerRegistration(binding.Id, binding.ServiceOrigin, binding.KeyId, binding.Revision);
        }
        else
        {
            if (binding is null || binding.Revoked) throw new UnauthorizedAccessException();
            if (command.Action == "revoke-binding")
            {
                if (binding.Revision != command.ExpectedRevision) throw new InvalidOperationException("Stale binding.");
                binding.Revoked = true; binding.Revision++; result = new OwnerAccepted(true);
            }
            else if (command.Action is "grant" or "revoke-grant")
            {
                var grant = await db.OwnerGrants.SingleOrDefaultAsync(x => x.BindingId == binding.Id && x.ActorId == command.ActorId, ct);
                if (grant is null)
                {
                    if (command.Action != "grant" || command.ExpectedRevision != 0) throw new InvalidOperationException("Unknown grant.");
                    grant = AddGrant(command);
                }
                else
                {
                    if (grant.Revision != command.ExpectedRevision) throw new InvalidOperationException("Stale grant.");
                    if (command.Action == "grant") { ValidateGrant(command); grant.TenantScope = command.TenantScope!; grant.CapabilitiesJson = JsonSerializer.Serialize(command.Capabilities); grant.Revoked = false; }
                    else grant.Revoked = true;
                    grant.Revision++;
                }
                result = new { grant.ActorId, grant.Revision, grant.Revoked };
            }
            else throw new ArgumentException("Unknown local administrative action.");
        }
        db.Event(binding.Id, "owner.local." + command.Action, null, binding.Revision, clock.GetUtcNow(), operatorSubject: actor, target: command.ActorId.ToString("D"));
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); return result;
    }
    private OwnerGrant AddGrant(LocalOwnerCommand command)
    {
        ValidateGrant(command);
        var grant = new OwnerGrant { BindingId = command.BindingId, ActorId = command.ActorId, TenantScope = command.TenantScope!, CapabilitiesJson = JsonSerializer.Serialize(command.Capabilities) };
        db.OwnerGrants.Add(grant); return grant;
    }
    private static void ValidateGrant(LocalOwnerCommand command)
    {
        if (command.ActorId == Guid.Empty || command.TenantScope is null || command.Capabilities is null || command.Capabilities.Length is < 1 or > 4 || command.Capabilities.Distinct().Count() != command.Capabilities.Length || command.Capabilities.Any(x => !OwnerProtocol.Capabilities.Contains(x))) throw new ArgumentException("Choose explicit actor capabilities.");
        if (command.TenantScope != "*") Guards.Id(command.TenantScope);
        if (command.TenantScope != "*" && command.Capabilities.Any(x => x is OwnerProtocol.Import or OwnerProtocol.Approve)) throw new ArgumentException("Global provider administration requires explicit global scope.");
    }
}

public sealed class OwnerControl(ConnectionStore db, ServiceOptions options, RegistryService registry, TimeProvider clock,
    IEnumerable<IOAuthCredentialDocumentReader> readers)
{
    public async Task<object> Execute(HttpContext context, string action, CancellationToken ct)
    {
        OwnerFailureScope.SetStage(context, "authorization");
        // One write transaction serializes authority changes, nonce use, mutations and their audit events.
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var header = context.Request.Headers[OwnerProtocol.ProofHeader];
        if (header.Count != 1 || header[0] is not { Length: <= 8192 } encoded) throw new UnauthorizedAccessException();
        var pieces = encoded.Split('.'); if (pieces.Length != 2) throw new UnauthorizedAccessException();
        var unverified = JsonSerializer.Deserialize<DeploymentProof>(DeploymentProofCodec.Decode(pieces[0]), DeploymentProofCodec.Json) ?? throw new UnauthorizedAccessException();
        var binding = await db.OwnerBindings.SingleOrDefaultAsync(x => x.Id == unverified.DeploymentId && !x.Revoked, ct) ?? throw new UnauthorizedAccessException();
        using var key = DeploymentProofCodec.PublicKey(binding.PublicKey); var proof = DeploymentProofCodec.Verify(encoded, key);
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (binding.ServiceOrigin != options.PublicOrigin || proof.Audience != options.PublicOrigin + OwnerProtocol.AudienceSuffix || proof.KeyId != binding.KeyId || proof.DeploymentRevision != binding.Revision ||
            proof.Method != "POST" || context.Request.Method != "POST" || proof.PathAndQuery != context.Request.PathBase + context.Request.Path + context.Request.QueryString ||
            proof.IssuedAt > now + 5 || proof.IssuedAt < now - 30 || proof.ExpiresAt <= now || proof.ExpiresAt > proof.IssuedAt + 30 || proof.ExpiresAt <= proof.IssuedAt || proof.Nonce is not { Length: >= 43 and <= 64 }) throw new UnauthorizedAccessException();
        OwnerFailureScope.SetStage(context, "envelope");
        using var buffer = new MemoryStream(); var chunk = new byte[8192]; int count;
        while ((count = await context.Request.Body.ReadAsync(chunk, ct)) > 0) { if (buffer.Length + count > ConnectionProtocol.MaximumBodyBytes) throw new ArgumentException("Request exceeds limit."); buffer.Write(chunk, 0, count); }
        if (!DeploymentProofCodec.Equal(proof.BodySha256, DeploymentProofCodec.Hash(buffer.ToArray()))) throw new UnauthorizedAccessException();
        OwnerFailureScope.SetStage(context, "envelope");
        using var document = JsonDocument.Parse(buffer.ToArray()); RegistryService.CheckDuplicates(document.RootElement);
        var envelope = document.RootElement.Deserialize<OwnerRequest<JsonElement>>(DeploymentProofCodec.Json) ?? throw new ArgumentException("Missing request.");
        var grant = await db.OwnerGrants.SingleOrDefaultAsync(x => x.BindingId == binding.Id && x.ActorId == envelope.ActorId && !x.Revoked, ct) ?? throw new UnauthorizedAccessException();
        if (action != "access" && envelope.GrantRevision != grant.Revision) throw new UnauthorizedAccessException();
        var capabilities = JsonSerializer.Deserialize<string[]>(grant.CapabilitiesJson)!;
        var permission = action switch { "credentials/import" => OwnerProtocol.Import, "packages/approve" => OwnerProtocol.Approve, "deployments/enroll" => OwnerProtocol.Enroll, "deployments/revoke" => OwnerProtocol.Revoke, "access" => null, _ => throw new ArgumentException("Unknown operation.") };
        if (permission is not null && !capabilities.Contains(permission)) throw new UnauthorizedAccessException();
        db.OwnerNonces.Add(new() { BindingId = binding.Id, NonceHash = DeploymentProofCodec.Hash(proof.Nonce), ExpiresAt = proof.ExpiresAt });
        await db.SaveChangesAsync(ct); // Unique nonce constraint, still inside transaction.
        var actor = "owner:" + binding.Id.ToString("D") + "/user:" + grant.ActorId.ToString("D");
        T Payload<T>() { OwnerFailureScope.SetStage(context, "payload"); return envelope.Payload.Deserialize<T>(DeploymentProofCodec.Json) ?? throw new ArgumentException("Missing payload."); }
        void Tenant(string tenant) { OwnerFailureScope.SetStage(context, "tenant"); Guards.Id(tenant); if (grant.TenantScope != "*" && grant.TenantScope != tenant) throw new UnauthorizedAccessException(); }
        object result;
        switch (action)
        {
            case "access": result = new OwnerAccess(new(binding.Id, binding.ServiceOrigin, binding.KeyId, binding.Revision), grant.ActorId, grant.Revision, grant.TenantScope, capabilities); break;
            case "credentials/import":
                if (grant.TenantScope != "*") throw new UnauthorizedAccessException();
                var import = Payload<OwnerCredentialImport>();
                var reader = readers.SingleOrDefault(x => x.Format == import.Format) ?? throw new ArgumentException("Unknown credential format.");
                result = await registry.Configure(actor, reader.Read(import.ProfileId, import.Document, options.Callback(import.ProfileId)), ct); break;
            case "packages/approve":
                if (grant.TenantScope != "*") throw new UnauthorizedAccessException();
                await registry.Approve(actor, Payload<ApprovePackage>(), ct); result = new OwnerAccepted(true); break;
            case "deployments/enroll":
                var enroll = Payload<OwnerEnrollment>(); Tenant(enroll.TenantId);
                OwnerFailureScope.SetStage(context, "enrollment");
                result = await registry.Enroll(enroll.TenantId, actor, enroll.Deployment, ct, stage => OwnerFailureScope.SetStage(context, stage)); break;
            case "deployments/revoke":
                var revoke = Payload<OwnerRevocation>(); Tenant(revoke.TenantId);
                await registry.Revoke(revoke.TenantId, actor, revoke.DeploymentId, ct); result = new OwnerAccepted(true); break;
            default: throw new ArgumentException("Unknown operation.");
        }
        OwnerFailureScope.SetStage(context, "persistence");
        db.Event(binding.Id, "owner.request." + action.Replace('/', '.'), null, grant.Revision, clock.GetUtcNow(), operatorSubject: actor, target: grant.TenantScope);
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); return result;
    }
}

public static class OwnerEndpoints
{
    public static void MapOwnerControl(this IEndpointRouteBuilder endpoints)
    {
        foreach (var action in new[] { "access", "credentials/import", "packages/approve", "deployments/enroll", "deployments/revoke" })
        {
            var operation = action;
            endpoints.MapPost("/owner-control/v1/" + operation, async (HttpContext context, OwnerControl control, CancellationToken ct) =>
                Results.Ok(await control.Execute(context, operation, ct))).RequireRateLimiting("bounded");
        }
    }
}

internal static class OwnerKeyIdentity
{
    public static bool Same(string left, string right)
    {
        using var first = DeploymentProofCodec.PublicKey(left);
        using var second = DeploymentProofCodec.PublicKey(right);
        return first.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(second.ExportSubjectPublicKeyInfo());
    }
}
