using System.Text.Json;
using CSweet.Agent.Contracts.Packaging;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

internal sealed record StoredInventory(string? Subject, string? Name, string? Authority, ManagedResource[] Resources,
    string? PageToken, string[] SeenPageTokens, int Pages);

/// <summary>Only the reviewed identity/discovery GET mappings. No caller URL, capability or resource substitution.</summary>
public sealed class ConnectionDiscoveryService(ConnectionStore db, CredentialVault vault, RegistryService registry,
    ConnectionCredentialService credentials, IProviderApiTransport provider, TimeProvider clock)
{
    public async Task<ConnectionInventory> Discover(Deployment deployment, Guid id, CancellationToken ct)
    {
        var connection = await db.Connections.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        if (!await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == deployment.Id && x.Revision == deployment.Revision && !x.Revoked, ct)) throw new UnauthorizedAccessException();
        var (_, manifest, profile) = await registry.Resolve(connection.PackageDigest, ct);
        if (profile.Id != connection.ProfileId || profile.Revision != connection.ProfileRevision)
            throw new UnauthorizedAccessException("The connection requires renewed consent for this application binding.");
        if (connection.Status == "Ready" && connection.InventoryVerifiedAt > clock.GetUtcNow().AddHours(-manifest.Accounts!.Lifecycle.AuthorizationCheckHours))
            return View(connection, Read(connection));
        if (connection.Status == "Ready") { connection.Status = "AuthorizedPendingDiscovery"; connection.ProtectedInventory = ""; connection.Revision++; await db.SaveChangesAsync(ct); }
        var token = await credentials.Require(connection, ct);
        if (connection.LeaseUntil > clock.GetUtcNow()) throw new InvalidOperationException("Discovery is already in progress.");
        var owner = Guid.NewGuid(); connection.LeaseOwner = owner; connection.LeaseUntil = clock.GetUtcNow().AddSeconds(30); connection.Revision++;
        await db.SaveChangesAsync(ct);
        try
        {
            var inventory = Read(connection); var account = manifest.Accounts!;
            async Task Revalidate()
            {
                await registry.Resolve(connection.PackageDigest, ct);
                var current = await db.Connections.AsNoTracking().SingleOrDefaultAsync(x => x.Id == connection.Id && x.LeaseOwner == owner &&
                    x.Status == "AuthorizedPendingDiscovery", ct);
                if (current is null || current.LeaseUntil <= clock.GetUtcNow() ||
                    !await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == deployment.Id && !x.Revoked && x.Revision == deployment.Revision, ct))
                    throw new UnauthorizedAccessException();
            }
            async Task<JsonElement> Invoke(string capability, JsonElement input)
            {
                var operation = manifest.ProviderOperations.Single(x => x.Capability == capability && x.Effect == "read" && x.Http is { Method: "GET", Bootstrap: true });
                var mapping = operation.Http!;
                if (!manifest.Provides.Any(x => x.Name == capability && x.RiskClass == "bootstrap") || mapping.Connection != account.Connection ||
                    mapping.SecretResponseFields.Count != 0 || mapping.MediaInput is not null || mapping.ResourceChecks.Count != 0 || mapping.BodyInputs.Count != 0 ||
                    mapping.ScopeSets.Except(JsonSerializer.Deserialize<string[]>(connection.GrantedScopeSetsJson)!, StringComparer.Ordinal).Any()) throw new UnauthorizedAccessException();
                ManagedRequestSchemaValidator.ValidateSchema(operation.InputSchema);
                ManagedRequestSchemaValidator.Validate(input, operation.InputSchema);
                var query = new SortedDictionary<string, string>(mapping.QueryConstants.ToDictionary(x => x.Key, x => x.Value), StringComparer.Ordinal);
                foreach (var field in mapping.QueryInputs)
                    if (At(input, field.Value) is { } value) query.Add(field.Key, value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText());
                var endpoint = Guards.Https(mapping.Endpoint);
                var declaration = manifest.Connections.Single();
                if (!declaration.AllowedOrigins.Contains(endpoint.GetLeftPart(UriPartial.Authority), StringComparer.Ordinal)) throw new UnauthorizedAccessException();
                var url = mapping.Endpoint + (query.Count == 0 ? "" : "?" + string.Join('&', query.Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value))));
                await Revalidate(); var result = await provider.Read(new Uri(url), token.AccessToken, ct);
                RegistryService.CheckDuplicates(result); ManagedRequestSchemaValidator.Validate(result, operation.OutputSchema);
                await Revalidate(); return result;
            }
            if (account.Identity is { } identity && inventory.Subject is null)
            {
                var evidence = await Invoke(identity.Capability, JsonSerializer.SerializeToElement(new { }));
                var subject = Text(evidence, identity.SubjectPointer, true)!;
                inventory = inventory with
                {
                    Subject = subject,
                    Name = identity.NamePointer is null ? null : Text(evidence, identity.NamePointer, false),
                    Authority = manifest.ProviderOperations.Single(x => x.Capability == identity.Capability).Http!.Endpoint
                };
                if (connection.SubjectHash is { } expected && expected != DeploymentProofCodec.Hash((profile.RevocationGroup ?? profile.Id) + "\n" + subject))
                    throw new UnauthorizedAccessException("The authorized provider identity changed.");
            }
            if (inventory.Pages >= 1000) throw new InvalidOperationException("Discovery exceeded the reviewed budget.");
            var input = new Dictionary<string, string>();
            if (inventory.PageToken is { } cursor) input.Add(account.PageTokenInput ?? throw new InvalidOperationException(), cursor);
            var page = await Invoke(account.DiscoveryCapability, JsonSerializer.SerializeToElement(input));
            var projection = account.ResourceProjection;
            if (At(page, projection.ItemsPointer) is not { ValueKind: JsonValueKind.Array } items || items.GetArrayLength() > 200)
                throw new InvalidOperationException("Invalid resource page.");
            var resources = inventory.Resources.ToDictionary(x => x.Id, StringComparer.Ordinal);
            foreach (var item in items.EnumerateArray())
            {
                var resource = new ManagedResource(Text(item, projection.IdPointer, true)!, Text(item, projection.NamePointer, true)!,
                    projection.HandlePointer is null ? null : Text(item, projection.HandlePointer, false));
                if (resources.TryGetValue(resource.Id, out var existing) && existing != resource) throw new InvalidOperationException("Conflicting provider resource identity.");
                resources[resource.Id] = resource;
            }
            if (resources.Count > account.MaximumResources) throw new InvalidOperationException("Resource limit exceeded.");
            var next = projection.NextPageTokenPointer is null ? null : Text(page, projection.NextPageTokenPointer, false, 2048);
            if (next is not null && (account.PageTokenInput is null || inventory.SeenPageTokens.Contains(next, StringComparer.Ordinal)))
                throw new InvalidOperationException("Repeated discovery cursor.");
            await Revalidate(); await db.Entry(connection).ReloadAsync(ct);
            inventory = inventory with
            {
                Resources = resources.Values.OrderBy(x => x.Id, StringComparer.Ordinal).ToArray(),
                PageToken = next,
                SeenPageTokens = next is null ? inventory.SeenPageTokens : [.. inventory.SeenPageTokens, next],
                Pages = inventory.Pages + 1
            };
            connection.ProtectedInventory = vault.Seal("inventory:" + connection.Id, JsonSerializer.Serialize(inventory));
            connection.SubjectHash = inventory.Subject is null ? null : DeploymentProofCodec.Hash((profile.RevocationGroup ?? profile.Id) + "\n" + inventory.Subject);
            if (next is null) { connection.Status = "Ready"; connection.InventoryVerifiedAt = clock.GetUtcNow(); }
            connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++;
            db.Event(connection.DeploymentId, next is null ? "connection.ready" : "connection.discovery-progress", connection.Id, connection.Revision, clock.GetUtcNow());
            await db.SaveChangesAsync(ct); return View(connection, inventory);
        }
        finally
        {
            await db.Entry(connection).ReloadAsync(CancellationToken.None);
            if (connection.LeaseOwner == owner) { connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++; await db.SaveChangesAsync(CancellationToken.None); }
        }
    }
    private StoredInventory Read(ManagedConnection c) => string.IsNullOrEmpty(c.ProtectedInventory)
        ? new(null, null, null, [], null, [], 0) : JsonSerializer.Deserialize<StoredInventory>(vault.Open("inventory:" + c.Id, c.ProtectedInventory))!;
    private static ConnectionInventory View(ManagedConnection c, StoredInventory inventory) => new(c.Id, c.Status, c.Revision,
        inventory.Subject, inventory.Name, inventory.Authority, inventory.Resources, JsonSerializer.Deserialize<string[]>(c.GrantedScopeSetsJson)!);
    internal static JsonElement? At(JsonElement value, string pointer)
    {
        foreach (var part in pointer.Split('/').Skip(1))
        { if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(part.Replace("~1", "/").Replace("~0", "~"), out var child)) value = child; else return null; }
        return value;
    }
    private static string? Text(JsonElement value, string pointer, bool required, int maximum = 256)
    {
        var field = At(value, pointer); if (!required && (field is null || field.Value.ValueKind == JsonValueKind.Null)) return null;
        if (field is not { ValueKind: JsonValueKind.String } || field.Value.GetString() is not { } text ||
            text.Length > maximum || text.Any(char.IsControl) || required && string.IsNullOrWhiteSpace(text)) throw new InvalidOperationException("Invalid provider field.");
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}
