using System.Text.Json;
using System.Text.Json.Nodes;
using CSweet.Agent.Contracts.Packaging;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Durable declaration-owned resumable exchanges. A lost initiation is never repeated.
/// Session URLs and operation content stay encrypted at the service. Core owns human approval.</summary>
public sealed class ManagedMediaService(ConnectionStore db, CredentialVault vault, RegistryService registry,
    ConnectionCredentialService credentials, IProviderApiTransport reads, IProviderMediaTransport media,
    ServiceOptions options, TimeProvider clock)
{
    private const long MaximumAssetBytes = 256L * 1024 * 1024 * 1024;
    private const int Alignment = 256 * 1024;
    private long Now => clock.GetUtcNow().ToUnixTimeSeconds();

    public async Task<ManagedMediaResult> Begin(Deployment deployment, Guid connection, ManagedMediaRequest request, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); ct = deadline.Token;
        var authority = await Require(deployment, connection, request, true, ct);
        var binding = request.BindingHash(connection);
        var idempotency = DeploymentProofCodec.Hash(JsonSerializer.Serialize(new { connection, request.Operation.RequesterInstallationId,
            request.Operation.Capability, request.IdempotencyKey }, DeploymentProofCodec.Json));
        ManagedMediaTransfer row; var owner = Guid.NewGuid();
        await using (var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct))
        {
            var existing = await db.MediaTransfers.SingleOrDefaultAsync(x => x.DeploymentId == deployment.Id && x.IdempotencyHash == idempotency, ct);
            if (existing is not null)
            {
                authority = await Require(deployment, connection, request, true, ct);
                if (existing.ConnectionId != connection || existing.BindingHash != binding || existing.PolicyHash != authority.Policy || existing.ValidUntil <= Now ||
                    existing.LeaseOwner is not null || existing.LeaseUntil != 0)
                    throw new UnauthorizedAccessException();
                if (existing.State is not ("Ready" or "ProbeRequired" or "Completed")) throw new InvalidOperationException("Initiation is already recorded; do not initiate a replacement.");
                var receipt = View(existing);
                await transaction.CommitAsync(ct); return receipt;
            }
            authority = await Require(deployment, connection, request, true, ct);
            row = new() { Id = Guid.NewGuid(), DeploymentId = deployment.Id, ConnectionId = connection, IdempotencyHash = idempotency,
                BindingHash = binding, PolicyHash = authority.Policy, ValidUntil = request.ValidUntil, LeaseOwner = owner, LeaseUntil = Now + 40 };
            row.ProtectedRequest = vault.Seal(Purpose(row, "plan"), JsonSerializer.Serialize(request, DeploymentProofCodec.Json));
            db.MediaTransfers.Add(row); db.Event(deployment.Id, "media.initiation-recorded", connection, row.Revision, clock.GetUtcNow());
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        }
        try
        {
            var token = await Credential(deployment, connection, request, ct);
            await Checks(authority.Manifest, request, token, ct);
            await RequireOwned(deployment, row, request, owner, ct);
            var destination = Destination(authority.Manifest, request);
            var response = await media.Exchange(new(destination, true, false, Body(authority.Manifest, request), request.ContentType, request.SizeBytes, 0), token, ct);
            if (response.StatusCode is not (200 or 201) || response.SessionLocation is null)
                throw new InvalidOperationException("Initiation was not confirmed; do not initiate a replacement.");
            var session = Session(destination, response.SessionLocation);
            await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
            await db.Entry(row).ReloadAsync(ct); await RequireOwned(deployment, row, request, owner, ct);
            row.ProtectedSession = vault.Seal(Purpose(row, "session"), session.AbsoluteUri);
            row.State = "Ready"; row.LastStatus = response.StatusCode; row.RetryAt = response.RetryAt;
            row.LeaseOwner = null; row.LeaseUntil = 0; row.Revision++;
            db.Event(deployment.Id, "media.session-created", connection, row.Revision, clock.GetUtcNow());
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct); return View(row);
        }
        catch { await FenceFailure(row.Id, owner, true); throw; }
    }

    public async Task<ManagedMediaResult> Exchange(Deployment deployment, Guid id, string binding, long? offset, byte[] chunk, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); ct = deadline.Token;
        Guards.Digest(binding);
        var row = await db.MediaTransfers.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id && x.BindingHash == binding, ct)
            ?? throw new UnauthorizedAccessException();
        var request = ReadPlan(row); var authority = await Require(deployment, row.ConnectionId, request, false, ct);
        if (row.PolicyHash != authority.Policy || row.ValidUntil <= Now) throw new UnauthorizedAccessException();
        var owner = Guid.NewGuid();
        await using (var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct))
        {
            await db.Entry(row).ReloadAsync(ct);
            authority = await Require(deployment, row.ConnectionId, request, false, ct);
            if (row.BindingHash != binding || row.BindingHash != request.BindingHash(row.ConnectionId) || row.PolicyHash != authority.Policy || row.ValidUntil <= Now)
                throw new UnauthorizedAccessException();
            if (row.State == "Completed")
            {
                if (row.LeaseOwner is not null || row.LeaseUntil != 0) throw new UnauthorizedAccessException();
                var receipt = View(row);
                await transaction.CommitAsync(ct); return receipt;
            }
            if (row.State is not ("Ready" or "ProbeRequired" or "InFlight") || row.LeaseOwner is not null && row.LeaseUntil > Now || row.RetryAt > Now || row.Failures >= 8)
                throw new InvalidOperationException("The transfer is not available for this exchange.");
            if (offset is { } start)
            {
                if (row.State != "Ready" || row.LeaseOwner is not null || start != row.Offset || chunk.Length is < 1 or > ManagedExecutionProtocol.MaximumChunkBytes ||
                    start < 0 || start >= request.SizeBytes || chunk.Length > request.SizeBytes - start ||
                    start + chunk.Length != request.SizeBytes && chunk.Length % Alignment != 0)
                    throw new InvalidOperationException("The range requires an authoritative probe or does not match the approved asset.");
                row.MaximumSentBytes = Math.Max(row.MaximumSentBytes, start + chunk.Length);
            }
            else if (chunk.Length != 0) throw new ArgumentException("Probes cannot contain media.");
            row.State = "InFlight"; row.LeaseOwner = owner; row.LeaseUntil = Now + 40; row.Revision++;
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        }
        try
        {
            var token = await Credential(deployment, row.ConnectionId, request, ct);
            await Checks(authority.Manifest, request, token, ct);
            await RequireOwned(deployment, row, request, owner, ct);
            var session = Session(Destination(authority.Manifest, request), vault.Open(Purpose(row, "session"), row.ProtectedSession));
            var response = await media.Exchange(new(session, false, offset is null, chunk, request.ContentType, request.SizeBytes, offset ?? 0), token, ct);
            if (response.StatusCode is 200 or 201)
            {
                if (row.MaximumSentBytes != request.SizeBytes || response.Result is not { } result) throw new InvalidOperationException("Completion preceded the approved bytes.");
                RelayJson.RequireBounded(result); RegistryService.CheckDuplicates(result);
                var operation = authority.Manifest.ProviderOperations.Single(x => x.Capability == request.Operation.Capability);
                ManagedRequestSchemaValidator.Validate(result, operation.OutputSchema);
                ManagedRequestSchemaValidator.Validate(result, authority.Manifest.Provides.Single(x => x.Name == operation.Capability).OutputSchema);
                RelayJson.RequireResource(result, operation.Http!.ResponseResourcePointers, request.Operation.ResourceId);
            }
            else if (response.StatusCode == 308)
            {
                if (response.CommittedBytes is not { } committed || committed < row.Offset || committed > row.MaximumSentBytes)
                    throw new InvalidOperationException("The upload acknowledgment regressed or exceeded sent bytes.");
            }
            else if (response.StatusCode is not (429 or 500 or 502 or 503 or 504)) throw new InvalidOperationException("The existing upload cannot safely continue.");
            await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
            await db.Entry(row).ReloadAsync(ct); await RequireOwned(deployment, row, request, owner, ct);
            if (response.StatusCode is 200 or 201)
            {
                row.ProtectedResult = vault.Seal(Purpose(row, "result"), response.Result!.Value.GetRawText());
                row.ProtectedSession = ""; row.State = "Completed"; row.Offset = request.SizeBytes;
                db.Event(deployment.Id, "media.completed", row.ConnectionId, row.Revision + 1, clock.GetUtcNow());
            }
            else if (response.StatusCode == 308)
            {
                var advanced = response.CommittedBytes!.Value > row.Offset;
                row.Offset = response.CommittedBytes.Value; row.State = "Ready";
                row.Failures = advanced || row.MaximumSentBytes == 0 ? 0 : row.Failures + 1;
            }
            else { row.State = "ProbeRequired"; row.Failures++; }
            if (row.Failures >= 8) row.State = "Indeterminate";
            row.LastStatus = response.StatusCode; row.RetryAt = response.RetryAt;
            row.LeaseOwner = null; row.LeaseUntil = 0; row.Revision++;
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
            if (row.State == "Indeterminate") throw new InvalidOperationException("Media recovery requires manual review.");
            return View(row);
        }
        catch { await FenceFailure(row.Id, owner, false); throw; }
    }

    public async Task<ManagedMediaResult> Cancel(Deployment deployment, Guid id, ManagedMediaControl control, CancellationToken ct)
    {
        Guards.Digest(control.BindingHash);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        if (!await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == deployment.Id && !x.Revoked && x.Revision == deployment.Revision, ct))
            throw new UnauthorizedAccessException();
        var row = await db.MediaTransfers.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id && x.BindingHash == control.BindingHash, ct)
            ?? throw new UnauthorizedAccessException();
        // Local fencing does not claim the provider aborted processing or deleted a video.
        if (row.State != "Cancelled")
        {
            row.State = "Cancelled"; row.ProtectedSession = ""; row.ProtectedResult = ""; row.LeaseOwner = null; row.LeaseUntil = 0; row.Revision++;
            db.Event(deployment.Id, "media.locally-cancelled", row.ConnectionId, row.Revision, clock.GetUtcNow()); await db.SaveChangesAsync(ct);
        }
        await transaction.CommitAsync(ct); return View(row);
    }

    public async Task Expire(CancellationToken ct)
    {
        foreach (var row in await db.MediaTransfers.Where(x => x.ValidUntil <= Now && x.State != "Expired").Take(100).ToArrayAsync(ct))
        {
            row.State = "Expired"; row.ProtectedSession = row.ProtectedRequest = row.ProtectedResult = "";
            row.LeaseOwner = null; row.LeaseUntil = 0; row.Revision++;
            db.Event(row.DeploymentId, "media.expired", row.ConnectionId, row.Revision, clock.GetUtcNow());
        }
        await db.SaveChangesAsync(ct);
    }

    private async Task<(AgentManifest Manifest, string Policy)> Require(Deployment deployment, Guid id, ManagedMediaRequest request, bool beginning, CancellationToken ct)
    {
        var operation = request.Operation; Guards.Id(operation.TenantId); Guards.Digest(operation.PackageDigest); Guards.Digest(operation.CorePlanHash);
        Guards.Digest(request.AssetSha256); Guards.Text(request.IdempotencyKey, 160); Guards.Text(request.ApprovalReference, 128);
        Guards.Text(request.ContentType, 128);
        Guards.Text(operation.Capability, 256); Guards.Text(operation.ResourceId, 256);
        if (operation.TenantId != deployment.TenantId || operation.InstallationId == Guid.Empty || operation.RequesterInstallationId == Guid.Empty ||
            operation.Input.ValueKind != JsonValueKind.Object || JsonSerializer.SerializeToUtf8Bytes(operation.Input).Length > ManagedExecutionProtocol.MaximumInputBytes ||
            request.AssetId == Guid.Empty || request.SizeBytes is < 1 or > MaximumAssetBytes || request.ValidUntil <= Now || request.ValidUntil > Now + 86400 ||
            beginning && (operation.ExpiresAt <= Now || operation.ExpiresAt > Now + 60) ||
            !System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) || contentType.Parameters.Count != 0 ||
            !await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == deployment.Id && !x.Revoked && x.Revision == deployment.Revision && x.TenantId == operation.TenantId, ct))
            throw new UnauthorizedAccessException();
        var policy = ManagedExecutionPolicy.Require(options, deployment, operation.PackageDigest, true);
        var connection = await db.Connections.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        var (_, manifest, profile) = await registry.Resolve(operation.PackageDigest, ct);
        if (connection.InstallationId != operation.InstallationId || connection.PackageDigest != operation.PackageDigest || connection.ProfileId != profile.Id ||
            connection.ProfileRevision != profile.Revision || connection.Status != "Ready" || connection.LeaseOwner is not null || connection.LeaseUntil is not null ||
            connection.SubjectHash is null || connection.ProtectedCredentials.Length == 0 || connection.ProtectedInventory.Length == 0 ||
            connection.InventoryVerifiedAt is not { } verified || verified > clock.GetUtcNow() || verified <= clock.GetUtcNow().AddHours(-manifest.Accounts!.Lifecycle.AuthorizationCheckHours))
            throw new UnauthorizedAccessException();
        var inventory = JsonSerializer.Deserialize<StoredInventory>(vault.Open("inventory:" + id, connection.ProtectedInventory)) ?? throw new UnauthorizedAccessException();
        var declaration = manifest.ProviderOperations.SingleOrDefault(x => x.Capability == operation.Capability) ?? throw new UnauthorizedAccessException();
        var mapping = declaration.Http ?? throw new UnauthorizedAccessException();
        if (declaration.Effect != "write" || mapping.Method != "POST" || mapping.Bootstrap || mapping.Connection != manifest.Accounts!.Connection ||
            mapping.MediaProtocol != "resumable-range.v1" || mapping.MediaInput is null || mapping.IfMatchInput is not null || mapping.SecretResponseFields.Count != 0 ||
            mapping.ResponseResourcePointers.Count == 0 ||
            mapping.ResourceChecks.Count > 8 || mapping.ScopeSets.Except(JsonSerializer.Deserialize<string[]>(connection.GrantedScopeSetsJson)!, StringComparer.Ordinal).Any() ||
            inventory.PageToken is not null || inventory.Resources.Count(x => x.Id == operation.ResourceId) != 1 ||
            // Without an explicit resource selector, reviewed account-level media semantics are
            // restricted to a singleton inventory. Never choose one of several account resources.
            mapping.BoundResourceQuery is null && inventory.Resources.Length != 1 ||
            RelayJson.At(operation.Input, mapping.MediaInput) is not { ValueKind: JsonValueKind.String } asset || !Guid.TryParse(asset.GetString(), out var assetId) || assetId != request.AssetId)
            throw new UnauthorizedAccessException();
        ManagedRequestSchemaValidator.ValidateSchema(declaration.InputSchema); ManagedRequestSchemaValidator.Validate(operation.Input, declaration.InputSchema);
        ManagedRequestSchemaValidator.ValidateSchema(declaration.OutputSchema);
        ManagedRequestSchemaValidator.ValidateSchema(manifest.Provides.Single(x => x.Name == declaration.Capability).OutputSchema);
        _ = Destination(manifest, request); return (manifest, policy);
    }
    private async Task RequireOwned(Deployment deployment, ManagedMediaTransfer row, ManagedMediaRequest request, Guid owner, CancellationToken ct)
    {
        var current = await db.MediaTransfers.AsNoTracking().SingleAsync(x => x.Id == row.Id, ct);
        var authority = await Require(deployment, row.ConnectionId, request, false, ct);
        if (current.LeaseOwner != owner || current.LeaseUntil <= Now || current.State is not ("Starting" or "InFlight") ||
            current.PolicyHash != authority.Policy || current.BindingHash != request.BindingHash(row.ConnectionId)) throw new UnauthorizedAccessException();
    }
    private async Task<string> Credential(Deployment deployment, Guid connection, ManagedMediaRequest request, CancellationToken ct)
    {
        var tracked = await db.Connections.SingleAsync(x => x.Id == connection, ct);
        var credential = await credentials.Require(tracked, ct); await Require(deployment, connection, request, false, ct); return credential.AccessToken;
    }
    private async Task Checks(AgentManifest manifest, ManagedMediaRequest request, string token, CancellationToken ct)
    {
        foreach (var check in manifest.ProviderOperations.Single(x => x.Capability == request.Operation.Capability).Http!.ResourceChecks)
        {
            var value = RelayJson.At(request.Operation.Input, check.InputPointer) ?? throw new UnauthorizedAccessException();
            var uri = UriFor(manifest, check.Endpoint, check.QueryConstants.Append(new KeyValuePair<string, string>(check.ResourceQuery, RelayJson.Scalar(value))));
            var evidence = await reads.Read(uri, token, ct); RelayJson.RequireBounded(evidence); RegistryService.CheckDuplicates(evidence);
            if (RelayJson.At(evidence, check.OwnerPointer) is not { ValueKind: JsonValueKind.String } owner || owner.GetString() != request.Operation.ResourceId)
                throw new UnauthorizedAccessException();
        }
    }
    private static Uri Destination(AgentManifest manifest, ManagedMediaRequest request)
    {
        var mapping = manifest.ProviderOperations.Single(x => x.Capability == request.Operation.Capability).Http!;
        var query = new SortedDictionary<string, string>(mapping.QueryConstants.ToDictionary(x => x.Key, x => x.Value), StringComparer.Ordinal);
        foreach (var field in mapping.QueryInputs)
            if (RelayJson.At(request.Operation.Input, field.Value) is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) } value) query.Add(field.Key, RelayJson.Scalar(value));
        if (mapping.BoundResourceQuery is not null) query.Add(mapping.BoundResourceQuery, mapping.BoundResourceQueryPrefix + request.Operation.ResourceId);
        return UriFor(manifest, mapping.Endpoint, query);
    }
    private static Uri UriFor(AgentManifest manifest, string endpoint, IEnumerable<KeyValuePair<string, string>> query)
    {
        var uri = Guards.Https(endpoint);
        if (!manifest.Connections.Single(x => x.Id == manifest.Accounts!.Connection).AllowedOrigins.Contains(uri.GetLeftPart(UriPartial.Authority), StringComparer.Ordinal)) throw new UnauthorizedAccessException();
        return new(endpoint + "?" + string.Join('&', query.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value))));
    }
    private static byte[] Body(AgentManifest manifest, ManagedMediaRequest request)
    {
        var mapping = manifest.ProviderOperations.Single(x => x.Capability == request.Operation.Capability).Http!;
        var body = mapping.BodyConstants is { } constants ? JsonNode.Parse(constants.GetRawText()) as JsonObject ?? throw new UnauthorizedAccessException() : new JsonObject();
        foreach (var field in mapping.BodyInputs.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            if (RelayJson.At(request.Operation.Input, field.Value) is not { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) } value) continue;
            var parts = field.Key.Split('/').Skip(1).Select(x => x.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal)).ToArray();
            JsonObject target = body;
            foreach (var part in parts[..^1]) { if (target[part] is null) target[part] = new JsonObject(); target = target[part] as JsonObject ?? throw new UnauthorizedAccessException(); }
            target[parts[^1]] = JsonNode.Parse(value.GetRawText());
        }
        return JsonSerializer.SerializeToUtf8Bytes(body);
    }
    private static Uri Session(Uri initiation, string location)
    {
        if (location.Length > 16384 || location.Any(char.IsControl) || !Uri.TryCreate(location, UriKind.Absolute, out var session) ||
            session.Scheme != "https" || !session.IsDefaultPort || session.IsLoopback || session.HostNameType != UriHostNameType.Dns ||
            !string.IsNullOrEmpty(session.UserInfo) || !string.IsNullOrEmpty(session.Fragment) ||
            session.GetLeftPart(UriPartial.Authority) != initiation.GetLeftPart(UriPartial.Authority) || session.AbsolutePath != initiation.AbsolutePath)
            throw new UnauthorizedAccessException();
        return session;
    }
    private ManagedMediaRequest ReadPlan(ManagedMediaTransfer row) => JsonSerializer.Deserialize<ManagedMediaRequest>(vault.Open(Purpose(row, "plan"), row.ProtectedRequest), DeploymentProofCodec.Json)
        ?? throw new UnauthorizedAccessException();
    private ManagedMediaResult View(ManagedMediaTransfer row)
    {
        JsonElement? result = null;
        if (row.State == "Completed" && row.ProtectedResult.Length > 0)
        { using var document = JsonDocument.Parse(vault.Open(Purpose(row, "result"), row.ProtectedResult)); result = document.RootElement.Clone(); }
        return new(row.Id, row.BindingHash, row.State, row.LastStatus, row.Offset, row.Revision, result, row.RetryAt);
    }
    private static string Purpose(ManagedMediaTransfer row, string kind) => $"media:{row.DeploymentId:D}:{row.Id:D}:{kind}";
    private async Task FenceFailure(Guid id, Guid owner, bool beginning)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        db.ChangeTracker.Clear();
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, deadline.Token);
        var row = await db.MediaTransfers.SingleAsync(x => x.Id == id, deadline.Token);
        if (row.LeaseOwner == owner)
        {
            row.Failures++; row.State = beginning || row.Failures >= 8 ? "Indeterminate" : "ProbeRequired";
            row.LeaseOwner = null; row.LeaseUntil = 0; row.Revision++;
            db.Event(row.DeploymentId, beginning ? "media.initiation-uncertain" : "media.probe-required", row.ConnectionId, row.Revision, clock.GetUtcNow());
            await db.SaveChangesAsync(deadline.Token);
        }
        await transaction.CommitAsync(deadline.Token);
    }
}
