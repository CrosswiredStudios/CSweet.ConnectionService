using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Declaration-owned GET execution. Core owns its human/business grants; this boundary
/// independently owns deployment policy, consent, provider destinations and resource authority.</summary>
public sealed class ManagedReadService(ConnectionStore db, CredentialVault vault, RegistryService registry,
    ConnectionCredentialService credentials, IProviderApiTransport provider, ServiceOptions options, TimeProvider clock)
{
    public async Task<ManagedReadResult> Read(Deployment deployment, Guid id, ManagedReadRequest request, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30)); ct = timeout.Token;
        Guards.Id(request.TenantId); Guards.Digest(request.PackageDigest); Guards.Digest(request.CorePlanHash);
        Guards.Text(request.Capability, 256); Guards.Text(request.ResourceId, 256);
        if (request.InstallationId == Guid.Empty || request.RequesterInstallationId == Guid.Empty || request.TenantId != deployment.TenantId ||
            request.Input.ValueKind != JsonValueKind.Object || JsonSerializer.SerializeToUtf8Bytes(request.Input).Length > ManagedExecutionProtocol.MaximumInputBytes)
            throw new UnauthorizedAccessException();
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (request.ExpiresAt <= now || request.ExpiresAt > now + 60) throw new UnauthorizedAccessException();
        var policy = ManagedExecutionPolicy.Require(options, deployment, request.PackageDigest);
        var connection = await db.Connections.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        var (_, manifest, profile) = await registry.Resolve(request.PackageDigest, ct);
        if (connection.InstallationId != request.InstallationId || connection.PackageDigest != request.PackageDigest ||
            connection.ProfileId != profile.Id || connection.ProfileRevision != profile.Revision) throw new UnauthorizedAccessException();
        var operation = manifest.ProviderOperations.SingleOrDefault(x => x.Capability == request.Capability) ?? throw new UnauthorizedAccessException();
        var mapping = operation.Http ?? throw new UnauthorizedAccessException();
        var provided = manifest.Provides.SingleOrDefault(x => x.Name == request.Capability) ?? throw new UnauthorizedAccessException();
        if (operation.Effect != "read" || mapping.Method != "GET" || mapping.Bootstrap ||
            mapping.Connection != manifest.Accounts!.Connection || mapping.MediaInput is not null || mapping.MediaProtocol is not null ||
            mapping.SecretResponseFields.Count != 0 || mapping.BodyInputs.Count != 0 || mapping.BodyConstants is not null ||
            mapping.IfMatchInput is not null || mapping.ResourceChecks.Count > 8 ||
            mapping.ScopeSets.Except(JsonSerializer.Deserialize<string[]>(connection.GrantedScopeSetsJson)!, StringComparer.Ordinal).Any())
            throw new UnauthorizedAccessException();
        ManagedRequestSchemaValidator.ValidateSchema(operation.InputSchema);
        ManagedRequestSchemaValidator.ValidateSchema(operation.OutputSchema);
        ManagedRequestSchemaValidator.ValidateSchema(provided.OutputSchema);
        ManagedRequestSchemaValidator.Validate(request.Input, operation.InputSchema);
        RequireInventory(connection, request.ResourceId, manifest.Accounts.Lifecycle.AuthorizationCheckHours);
        // Refresh uses the service-owned vault and cannot add scope sets. Never export this receipt.
        var credential = await credentials.Require(connection, ct); var revision = connection.Revision;
        async Task Revalidate()
        {
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (request.ExpiresAt <= now || request.ExpiresAt > now + 60 ||
                ManagedExecutionPolicy.Require(options, deployment, request.PackageDigest) != policy ||
                !await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == deployment.Id && !x.Revoked && x.Revision == deployment.Revision && x.TenantId == request.TenantId, ct))
                throw new UnauthorizedAccessException();
            var (_, _, activeProfile) = await registry.Resolve(request.PackageDigest, ct);
            var current = await db.Connections.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id && x.Revision == revision, ct)
                ?? throw new UnauthorizedAccessException();
            if (current.InstallationId != request.InstallationId || current.ProfileId != activeProfile.Id || current.ProfileRevision != activeProfile.Revision)
                throw new UnauthorizedAccessException();
            RequireInventory(current, request.ResourceId, manifest.Accounts.Lifecycle.AuthorizationCheckHours);
        }
        await Revalidate();
        var declaration = manifest.Connections.Single(x => x.Id == mapping.Connection);
        Uri Destination(string endpoint, IEnumerable<KeyValuePair<string, string>> query)
        {
            var address = Guards.Https(endpoint);
            if (!declaration.AllowedOrigins.Contains(address.GetLeftPart(UriPartial.Authority), StringComparer.Ordinal)) throw new UnauthorizedAccessException();
            return new(endpoint + "?" + string.Join('&', query.OrderBy(x => x.Key, StringComparer.Ordinal)
                .Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value))));
        }
        foreach (var check in mapping.ResourceChecks)
        {
            var value = RelayJson.At(request.Input, check.InputPointer) ?? throw new UnauthorizedAccessException();
            var query = check.QueryConstants.Append(new KeyValuePair<string, string>(check.ResourceQuery, RelayJson.Scalar(value)));
            await Revalidate(); var evidence = await provider.Read(Destination(check.Endpoint, query), credential.AccessToken, ct);
            RegistryService.CheckDuplicates(evidence); RelayJson.RequireBounded(evidence);
            if (RelayJson.At(evidence, check.OwnerPointer) is not { ValueKind: JsonValueKind.String } owner || owner.GetString() != request.ResourceId)
                throw new UnauthorizedAccessException();
            await Revalidate();
        }
        var fields = new SortedDictionary<string, string>(mapping.QueryConstants.ToDictionary(x => x.Key, x => x.Value), StringComparer.Ordinal);
        foreach (var field in mapping.QueryInputs)
            if (RelayJson.At(request.Input, field.Value) is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) } value) fields.Add(field.Key, RelayJson.Scalar(value));
        if (mapping.BoundResourceQuery is not null) fields.Add(mapping.BoundResourceQuery, mapping.BoundResourceQueryPrefix + request.ResourceId);
        await Revalidate(); var result = await provider.Read(Destination(mapping.Endpoint, fields), credential.AccessToken, ct);
        RegistryService.CheckDuplicates(result); RelayJson.RequireBounded(result);
        ManagedRequestSchemaValidator.Validate(result, operation.OutputSchema);
        ManagedRequestSchemaValidator.Validate(result, provided.OutputSchema);
        RelayJson.RequireResource(result, mapping.ResponseResourcePointers, request.ResourceId);
        // Validation and content-free audit commit share the SQLite write fence. A concurrent
        // disconnect cannot become a new baseline between final validation and persistence.
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        await Revalidate();
        db.Event(deployment.Id, "connection.operation-read", id, revision, clock.GetUtcNow(), target: request.Capability);
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return new(id, revision, ManagedExecutionBinding.Hash(id, request), result.Clone());
    }

    private void RequireInventory(ManagedConnection connection, string resource, int hours)
    {
        var now = clock.GetUtcNow();
        if (connection.Status != "Ready" || connection.LeaseOwner is not null || connection.LeaseUntil is not null ||
            connection.SubjectHash is null || connection.ProtectedCredentials.Length == 0 || connection.ProtectedInventory.Length == 0 ||
            connection.InventoryVerifiedAt is not { } verified || verified > now || verified <= now.AddHours(-hours))
            throw new UnauthorizedAccessException();
        var inventory = JsonSerializer.Deserialize<StoredInventory>(vault.Open("inventory:" + connection.Id, connection.ProtectedInventory))
            ?? throw new UnauthorizedAccessException();
        if (inventory.Resources.Count(x => x.Id == resource) != 1 || inventory.PageToken is not null) throw new UnauthorizedAccessException();
    }
}

internal static class RelayJson
{
    internal static JsonElement? At(JsonElement value, string pointer)
    {
        foreach (var part in pointer.Split('/').Skip(1))
        {
            var key = part.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var child)) value = child;
            else if (value.ValueKind == JsonValueKind.Array && int.TryParse(key, out var index) && index >= 0 && index < value.GetArrayLength()) value = value[index];
            else return null;
        }
        return value;
    }
    internal static string Scalar(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!, JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true", JsonValueKind.False => "false", _ => throw new UnauthorizedAccessException()
    };
    internal static void RequireBounded(JsonElement result)
    { if (JsonSerializer.SerializeToUtf8Bytes(result).Length > ManagedExecutionProtocol.MaximumReadResultBytes) throw new InvalidOperationException("Provider result exceeds the relay limit."); }
    internal static void RequireResource(JsonElement result, IReadOnlyList<string> pointers, string expected)
    {
        if (pointers.Count > 8) throw new UnauthorizedAccessException();
        foreach (var pointer in pointers)
        {
            if (pointer.Length > 256 || !System.Text.RegularExpressions.Regex.IsMatch(pointer, @"\A(?:/(?:[A-Za-z0-9_-]+|\*))+\z") || pointer.Count(x => x == '*') > 1)
                throw new UnauthorizedAccessException();
            Check(result, pointer.Split('/').Skip(1).ToArray(), 0, expected);
        }
    }
    private static void Check(JsonElement value, string[] path, int index, string expected)
    {
        if (index == path.Length) { if (value.ValueKind != JsonValueKind.String || value.GetString() != expected) throw new UnauthorizedAccessException(); return; }
        if (path[index] == "*")
        { if (value.ValueKind != JsonValueKind.Array) throw new UnauthorizedAccessException(); foreach (var child in value.EnumerateArray()) Check(child, path, index + 1, expected); return; }
        var next = At(value, "/" + path[index]) ?? throw new UnauthorizedAccessException(); Check(next, path, index + 1, expected);
    }
}
