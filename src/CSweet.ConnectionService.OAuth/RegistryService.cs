using System.Text.Json;
using CSweet.Agent.Contracts.Packaging;
using CSweet.Agent.SDK;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed class RegistryService(ConnectionStore db, CredentialVault vault, ServiceOptions options, TimeProvider clock)
{
    public async Task<DeploymentRegistration> Enroll(string tenantId, string actor, EnrollDeployment request, CancellationToken ct, Action<string>? stage = null)
    {
        stage?.Invoke("tenant"); Guards.Id(tenantId);
        stage?.Invoke("key-id"); Guards.Id(request.KeyId);
        stage?.Invoke("name"); Guards.Text(request.Name, 200);
        stage?.Invoke("public-key");
        using var key = DeploymentProofCodec.PublicKey(request.PublicKey);
        if ((await db.OwnerBindings.Select(x => x.PublicKey).ToListAsync(ct)).Any(x => OwnerKeyIdentity.Same(x, request.PublicKey))) throw new UnauthorizedAccessException("Administrative keys cannot be customer keys.");
        stage?.Invoke("return");
        if (request.ReturnUris.Count is < 1 or > 20 || request.ReturnUris.Distinct(StringComparer.Ordinal).Count() != request.ReturnUris.Count) throw new ArgumentException("Choose exact return addresses.");
        foreach (var target in request.ReturnUris) { Guards.Text(target, 2048); options.ValidateReturn(target); }
        stage?.Invoke("persistence");
        var deployment = new Deployment
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = request.Name,
            PublicKey = request.PublicKey,
            KeyId = request.KeyId,
            ReturnUrisJson = JsonSerializer.Serialize(request.ReturnUris)
        };
        db.Deployments.Add(deployment); db.Event(deployment.Id, "deployment.enrolled", null, 1, clock.GetUtcNow(), operatorSubject: actor); await db.SaveChangesAsync(ct);
        return new(deployment.Id, tenantId, 1);
    }
    public async Task<DeploymentRegistration> Rotate(string tenantId, string actor, Guid id, RotateDeploymentKey request, CancellationToken ct)
    {
        Guards.Id(request.KeyId); using var key = DeploymentProofCodec.PublicKey(request.PublicKey);
        if ((await db.OwnerBindings.Select(x => x.PublicKey).ToListAsync(ct)).Any(x => OwnerKeyIdentity.Same(x, request.PublicKey))) throw new UnauthorizedAccessException("Administrative keys cannot be customer keys.");
        var d = await db.Deployments.SingleOrDefaultAsync(x => x.Id == id && x.TenantId == tenantId && !x.Revoked, ct) ?? throw new UnauthorizedAccessException();
        if (d.Revision != request.ExpectedRevision || d.KeyId == request.KeyId || d.PublicKey == request.PublicKey) throw new InvalidOperationException("Review the current deployment key.");
        d.PublicKey = request.PublicKey; d.KeyId = request.KeyId; d.Revision++;
        db.Event(id, "deployment.key-rotated", null, d.Revision, clock.GetUtcNow(), operatorSubject: actor); await db.SaveChangesAsync(ct); return new(id, tenantId, d.Revision);
    }
    public async Task Revoke(string tenantId, string actor, Guid id, CancellationToken ct)
    {
        await using var transaction = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var d = await db.Deployments.SingleOrDefaultAsync(x => x.Id == id && x.TenantId == tenantId, ct) ?? throw new UnauthorizedAccessException();
        if (d.Revoked) return;
        d.Revoked = true; d.Revision++;
        foreach (var connection in await db.Connections.Where(x => x.DeploymentId == id && x.Status != "RevocationPending" && x.Status != "Revoked").ToArrayAsync(ct))
        { connection.Status = "RevocationPending"; connection.Revision++; db.Event(id, "connection.fenced", connection.Id, connection.Revision, clock.GetUtcNow()); }
        db.Event(id, "deployment.revoked", null, d.Revision, clock.GetUtcNow(), operatorSubject: actor); await db.SaveChangesAsync(ct);
        if (transaction is not null) await transaction.CommitAsync(ct);
    }
    public async Task<ProfileAvailability> Configure(string actor, ConfigureProvider request, CancellationToken ct)
    {
        Guards.Id(request.Id); Guards.Text(request.ClientId, 512); Guards.Text(request.ClientSecret, 8192);
        Guards.Https(request.AuthorizationEndpoint); Guards.Https(request.TokenEndpoint); Guards.Https(request.RevocationEndpoint);
        if (request.RevocationGroup is not null) Guards.Id(request.RevocationGroup);
        var p = await db.Profiles.SingleOrDefaultAsync(x => x.Id == request.Id, ct);
        if (p is null) { p = new() { Id = request.Id }; db.Profiles.Add(p); }
        else
        {
            if (!p.Enabled) throw new InvalidOperationException("Disabled profile identities cannot be restored implicitly.");
            if (p.ClientId != request.ClientId || p.AuthorizationEndpoint != request.AuthorizationEndpoint || p.TokenEndpoint != request.TokenEndpoint || p.RevocationEndpoint != request.RevocationEndpoint || p.RevocationGroup != request.RevocationGroup)
                throw new InvalidOperationException("A different OAuth application requires a new profile identity and fresh consent.");
            p.SecretVersion++; // Secret rotation does not change public profile identity or inherit authority.
        }
        p.ClientId = request.ClientId; p.AuthorizationEndpoint = request.AuthorizationEndpoint; p.TokenEndpoint = request.TokenEndpoint; p.RevocationEndpoint = request.RevocationEndpoint;
        p.RevocationGroup = request.RevocationGroup;
        p.ProtectedSecret = vault.Seal("profile:" + p.Id, request.ClientSecret);
        db.Event(Guid.Empty, "profile.configured", null, p.SecretVersion, clock.GetUtcNow(), operatorSubject: actor, target: p.Id);
        await db.SaveChangesAsync(ct); return Availability(p);
    }
    public async Task Approve(string actor, ApprovePackage request, CancellationToken ct)
    {
        Guards.Digest(request.PackageDigest); Guards.Digest(request.ManifestSha256); Guards.Https(request.RepositoryUrl);
        if (request.SourceCommit.Length is not (40 or 64) || request.SourceCommit.Any(c => !char.IsAsciiHexDigit(c))) throw new ArgumentException("An immutable source commit is required.");
        if (request.ManifestJson.Length > 750000 || DeploymentProofCodec.Hash(request.ManifestJson) != request.ManifestSha256) throw new ArgumentException("The reviewed manifest digest does not match.");
        var manifest = ReadManifest(request.ManifestJson);
        var profile = await db.Profiles.SingleOrDefaultAsync(x => x.Id == request.ProfileId && x.Enabled && x.Revision == request.ProfileRevision, ct) ?? throw new InvalidOperationException("Review the active provider profile.");
        Match(manifest, profile);
        var existing = await db.Packages.FindAsync([request.PackageDigest], ct);
        if (existing is not null)
        {
            if (existing.Revoked || existing.ManifestSha256 != request.ManifestSha256 || existing.ProfileId != request.ProfileId || existing.ProfileRevision != request.ProfileRevision ||
                existing.RepositoryUrl != request.RepositoryUrl || existing.SourceCommit != request.SourceCommit) throw new InvalidOperationException("Approved package bindings are immutable.");
            return;
        }
        db.Packages.Add(new()
        {
            Digest = request.PackageDigest,
            ManifestSha256 = request.ManifestSha256,
            ManifestJson = request.ManifestJson,
            ProfileId = request.ProfileId,
            ProfileRevision = request.ProfileRevision,
            RepositoryUrl = request.RepositoryUrl,
            SourceCommit = request.SourceCommit
        });
        db.Event(Guid.Empty, "package.approved", null, 1, clock.GetUtcNow(), operatorSubject: actor, target: request.PackageDigest);
        await db.SaveChangesAsync(ct);
    }
    public async Task RevokePackage(string actor, string digest, CancellationToken ct)
    {
        await using var transaction = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var package = await db.Packages.SingleOrDefaultAsync(x => x.Digest == digest, ct) ?? throw new UnauthorizedAccessException();
        if (package.Revoked) return;
        package.Revoked = true;
        await Fence(await db.Connections.Where(x => x.PackageDigest == digest).ToArrayAsync(ct), ct);
        db.Event(Guid.Empty, "package.revoked", null, 1, clock.GetUtcNow(), operatorSubject: actor, target: digest); await db.SaveChangesAsync(ct);
        if (transaction is not null) await transaction.CommitAsync(ct);
    }
    public async Task DisableProfile(string actor, string id, CancellationToken ct)
    {
        await using var transaction = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var profile = await db.Profiles.SingleOrDefaultAsync(x => x.Id == id, ct) ?? throw new UnauthorizedAccessException();
        if (!profile.Enabled) return;
        profile.Enabled = false; profile.Revision++;
        await Fence(await db.Connections.Where(x => x.ProfileId == id).ToArrayAsync(ct), ct);
        db.Event(Guid.Empty, "profile.disabled", null, profile.Revision, clock.GetUtcNow(), operatorSubject: actor, target: id); await db.SaveChangesAsync(ct);
        if (transaction is not null) await transaction.CommitAsync(ct);
    }
    private Task Fence(ManagedConnection[] connections, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        foreach (var c in connections.Where(x => x.Status is not ("RevocationPending" or "Revoked")))
        { c.Status = "RevocationPending"; c.Revision++; db.Event(c.DeploymentId, "connection.fenced", c.Id, c.Revision, clock.GetUtcNow()); }
        return Task.CompletedTask;
    }
    public async Task<(PackageApproval Package, AgentManifest Manifest, ProviderProfile Profile)> Resolve(string digest, CancellationToken ct)
    {
        Guards.Digest(digest);
        var package = await db.Packages.AsNoTracking().SingleOrDefaultAsync(x => x.Digest == digest && !x.Revoked, ct) ?? throw new UnauthorizedAccessException();
        var profile = await db.Profiles.AsNoTracking().SingleOrDefaultAsync(x => x.Id == package.ProfileId && x.Enabled && x.Revision == package.ProfileRevision, ct) ?? throw new UnauthorizedAccessException();
        if (DeploymentProofCodec.Hash(package.ManifestJson) != package.ManifestSha256) throw new UnauthorizedAccessException();
        var manifest = ReadManifest(package.ManifestJson); Match(manifest, profile); return (package, manifest, profile);
    }
    public ProfileAvailability Availability(ProviderProfile p) => new(p.Id, p.Revision, DeploymentProofCodec.Hash(JsonSerializer.Serialize(new { p.Id, p.ClientId, p.AuthorizationEndpoint, p.TokenEndpoint, p.RevocationEndpoint, p.RevocationGroup, p.Revision })), options.Callback(p.Id));
    public static AgentManifest ReadManifest(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 }); CheckDuplicates(doc.RootElement);
        var manifest = doc.RootElement.Deserialize<AgentManifest>(DeploymentProofCodec.Json) ?? throw new ArgumentException("Invalid manifest.");
        AgentManifestLoader.Validate(manifest);
        if (manifest.Kind != "connector" || manifest.Accounts is null) throw new ArgumentException("Reviewed enterprise connector required.");
        return manifest;
    }
    private static void Match(AgentManifest manifest, ProviderProfile profile)
    {
        var connection = manifest.Connections.Single(); var provider = connection.Provider!;
        if (connection.ProviderProfile != profile.Id || provider.AuthorizationEndpoint != profile.AuthorizationEndpoint || provider.TokenEndpoint != profile.TokenEndpoint || provider.RevocationEndpoint != profile.RevocationEndpoint)
            throw new UnauthorizedAccessException("The reviewed provider profile does not match.");
    }
    internal static void CheckDuplicates(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject()) { if (!keys.Add(property.Name)) throw new ArgumentException("Duplicate JSON property."); CheckDuplicates(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) CheckDuplicates(item);
    }
}
