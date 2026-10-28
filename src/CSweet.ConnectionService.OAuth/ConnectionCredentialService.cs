using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Tokens stay inside this assembly. Durable leases serialize refresh across service instances.</summary>
public sealed class ConnectionCredentialService(ConnectionStore db, CredentialVault vault, RegistryService registry,
    IProviderOAuthTransport provider, TimeProvider clock, OAuthScopeConventions scopeConventions)
{
    internal async Task<StoredCredentials> Require(ManagedConnection connection, CancellationToken ct)
    {
        var (_, manifest, profile) = await registry.Resolve(connection.PackageDigest, ct);
        if (profile.Id != connection.ProfileId || profile.Revision != connection.ProfileRevision ||
            !await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == connection.DeploymentId && !x.Revoked, ct) ||
            connection.Status is not ("AuthorizedPendingDiscovery" or "Ready")) throw new UnauthorizedAccessException();
        var purpose = "connection:" + connection.DeploymentId + ":" + connection.Id;
        var credentials = JsonSerializer.Deserialize<StoredCredentials>(vault.Open(purpose, connection.ProtectedCredentials))!;
        if (credentials.ExpiresAt > clock.GetUtcNow().AddMinutes(1)) return credentials;
        if (connection.LeaseUntil > clock.GetUtcNow()) throw new InvalidOperationException("Connection maintenance is in progress.");
        if (string.IsNullOrWhiteSpace(credentials.RefreshToken)) throw new UnauthorizedAccessException();
        var previousStatus = connection.Status;
        connection.Status = "Refreshing"; connection.LeaseOwner = Guid.NewGuid(); connection.LeaseUntil = clock.GetUtcNow().AddSeconds(30); connection.Revision++;
        await db.SaveChangesAsync(ct);
        var owner = connection.LeaseOwner;
        try
        {
            var receipt = await provider.Refresh(profile, vault.Open("profile:" + profile.Id, profile.ProtectedSecret), credentials.RefreshToken, ct);
            Guards.Text(receipt.AccessToken, 8192); if (receipt.RefreshToken is not null) Guards.Text(receipt.RefreshToken, 8192);
            if (receipt.ExpiresIn is < 1 or > 86400) throw new InvalidOperationException("Invalid credential receipt.");
            var required = manifest.Connections.Single().ScopeSets.Where(s => JsonSerializer.Deserialize<string[]>(connection.GrantedScopeSetsJson)!.Contains(s.Id))
                .SelectMany(s => s.Scopes).ToHashSet(StringComparer.Ordinal);
            if (receipt.Scopes is { } scopes && (scopes.Length > 100 || scopes.Any(x => x.Length > 2048 || x.Any(char.IsControl)) ||
                scopeConventions.Canonical(profile, required).Except(scopeConventions.Canonical(profile, scopes), StringComparer.Ordinal).Any()))
                throw new UnauthorizedAccessException("Refreshed permissions no longer cover the reviewed grant.");
            // Never derive new GrantedScopeSets from a refresh response, including provider incremental-consent unions.
            await db.Entry(connection).ReloadAsync(ct);
            await registry.Resolve(connection.PackageDigest, ct);
            if (connection.LeaseOwner != owner || connection.Status != "Refreshing" || connection.LeaseUntil <= clock.GetUtcNow() ||
                !await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == connection.DeploymentId && !x.Revoked, ct)) throw new UnauthorizedAccessException();
            credentials = new(receipt.AccessToken, receipt.RefreshToken ?? credentials.RefreshToken, clock.GetUtcNow().AddSeconds(receipt.ExpiresIn));
            connection.ProtectedCredentials = vault.Seal(purpose, JsonSerializer.Serialize(credentials));
            connection.Status = previousStatus;
            connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++;
            db.Event(connection.DeploymentId, "connection.refreshed", connection.Id, connection.Revision, clock.GetUtcNow()); await db.SaveChangesAsync(ct);
            return credentials;
        }
        catch
        {
            // Never replay a possibly rotated refresh token after an indeterminate provider outcome.
            await db.Entry(connection).ReloadAsync(CancellationToken.None);
            if (connection.LeaseOwner == owner && connection.Status == "Refreshing")
            {
                connection.Status = "ConnectionRequired"; connection.FailureCode = "refresh_outcome_requires_reauthorization";
                connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++;
                db.Event(connection.DeploymentId, "connection.reauthorization-required", connection.Id, connection.Revision, clock.GetUtcNow());
                await db.SaveChangesAsync(CancellationToken.None);
            }
            throw;
        }
    }
}
