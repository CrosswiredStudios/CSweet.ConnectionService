using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Provider confirmation and primary credential erasure. Backup erasure is a separate operator obligation.</summary>
public sealed class ConnectionRevocationService(ConnectionStore db, CredentialVault vault, IProviderOAuthTransport provider, TimeProvider clock)
{
    public async Task Process(CancellationToken ct)
    {
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        var pending = await db.Connections.Where(x => x.Status == "RevocationPending" && x.NextRevocationAttempt <= now).OrderBy(x => x.NextRevocationAttempt).Take(100).ToArrayAsync(ct);
        foreach (var connection in pending.Where(x => x.LeaseUntil <= clock.GetUtcNow() || x.LeaseUntil is null))
        {
            var owner = Guid.NewGuid(); connection.LeaseOwner = owner; connection.LeaseUntil = clock.GetUtcNow().AddSeconds(30);
            connection.RevocationRequestedAt ??= clock.GetUtcNow(); connection.RevocationAttempts++; connection.Revision++;
            connection.NextRevocationAttempt = now + Math.Min(300, 30 * connection.RevocationAttempts);
            try { await db.SaveChangesAsync(ct); } catch (DbUpdateConcurrencyException) { continue; }
            try
            {
                var profile = await db.Profiles.AsNoTracking().SingleAsync(x => x.Id == connection.ProfileId, ct);
                if (connection.ProtectedCredentials.Length != 0)
                {
                    var stored = JsonSerializer.Deserialize<StoredCredentials>(vault.Open("connection:" + connection.DeploymentId + ":" + connection.Id, connection.ProtectedCredentials))!;
                    if (!await provider.Revoke(profile, vault.Open("profile:" + profile.Id, profile.ProtectedSecret), stored.RefreshToken ?? stored.AccessToken, ct)) continue;
                }
                else if (connection.RevokedAt is null) continue;
                await using var transaction = await db.Database.BeginTransactionAsync(ct);
                await db.Entry(connection).ReloadAsync(ct);
                if (connection.LeaseOwner != owner || connection.Status != "RevocationPending") continue;
                if (profile.RevocationGroup is { } group && connection.SubjectHash is { } subject)
                {
                    var profiles = await db.Profiles.Where(x => x.RevocationGroup == group).Select(x => x.Id).ToArrayAsync(ct);
                    foreach (var sibling in await db.Connections.Where(x => x.Id != connection.Id && profiles.Contains(x.ProfileId) &&
                        x.SubjectHash == subject && x.Status != "Revoked" && x.Status != "RevocationPending").ToArrayAsync(ct))
                    {
                        sibling.Status = "ConnectionRequired"; sibling.Revision++; sibling.ProtectedCredentials = ""; sibling.ProtectedInventory = "";
                        sibling.LeaseOwner = null; sibling.LeaseUntil = null;
                        sibling.RevokedAt = clock.GetUtcNow();
                        db.Event(sibling.DeploymentId, "connection.reauthorization-required", sibling.Id, sibling.Revision, clock.GetUtcNow());
                    }
                }
                connection.ProtectedCredentials = ""; connection.ProtectedInventory = ""; connection.SubjectHash = null;
                connection.GrantedScopeSetsJson = "[]"; connection.Status = "Revoked"; connection.RevokedAt = clock.GetUtcNow();
                connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++;
                db.Event(connection.DeploymentId, "connection.provider-revoked-primary-erased", connection.Id, connection.Revision, clock.GetUtcNow());
                await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
            }
            catch (Exception error) when (error is HttpRequestException or InvalidOperationException or JsonException or NotSupportedException or System.Security.Cryptography.CryptographicException ||
                error is OperationCanceledException && !ct.IsCancellationRequested)
            { /* Retain a real pending obligation, not a fabricated receipt. */ }
        }
    }
}
