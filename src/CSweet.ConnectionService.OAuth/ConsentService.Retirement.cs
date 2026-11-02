using System.Text.Json;
using CSweet.Agent.Contracts.Packaging;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed partial class ConsentService
{
    private const string RetiredEvent = "connection.superseded-primary-erased";
    private const string RecoveredEvent = "connection.revoked-replacement-linked";

    public async Task<ConnectionSnapshot> Supersede(Deployment deployment, Guid id, Guid replacementId, CancellationToken ct)
    {
        if (id == replacementId) throw new ArgumentException("A separate replacement is required.");
        // SQLite's immediate serializable write reservation includes all authority reads and
        // the receipt/outbox commit. No provider request, credential unsealing or revocation occurs.
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        await Active(deployment.Id, deployment.Revision, ct);
        var previous = await db.Connections.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        var replacement = await db.Connections.SingleOrDefaultAsync(x => x.Id == replacementId && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        if (previous.InstallationId != replacement.InstallationId || previous.ProfileId != replacement.ProfileId)
            throw new UnauthorizedAccessException();
        var links = await db.Events.AsNoTracking().Where(x => x.DeploymentId == deployment.Id && x.ConnectionId == id &&
            (x.Kind == RetiredEvent || x.Kind == RecoveredEvent)).Select(x => new { x.Kind, x.Target }).Take(2).ToArrayAsync(ct);
        if (links.Length != 0)
        {
            // A durable receipt remains valid after a later replacement disconnect. It cannot
            // retire another candidate, restore either connection or create an execution grant.
            if (links.Length != 1 || links[0].Target != replacementId.ToString("D") ||
                previous.Status != (links[0].Kind == RecoveredEvent ? "Revoked" : "Superseded")) throw new UnauthorizedAccessException();
            return new(previous.Id, previous.Status, previous.Revision, []);
        }
        var (_, manifest, profile) = await registry.Resolve(replacement.PackageDigest, ct);
        var now = clock.GetUtcNow();
        if (replacement.Status != "Ready" || replacement.ProfileId != profile.Id || replacement.ProfileRevision != profile.Revision ||
            string.IsNullOrEmpty(replacement.SubjectHash) || string.IsNullOrEmpty(replacement.ProtectedCredentials) || string.IsNullOrEmpty(replacement.ProtectedInventory) ||
            replacement.InventoryVerifiedAt is null || replacement.InventoryVerifiedAt <= now.AddHours(-1) || replacement.InventoryVerifiedAt > now ||
            replacement.LeaseOwner is not null || replacement.LeaseUntil is not null) throw new UnauthorizedAccessException();

        var recovered = previous.Status == "Revoked";
        if (recovered) await RequireExpiredUnverifiedRecovery(previous, replacement, manifest, ct);
        else
        {
            if (previous.Status is not ("Ready" or "ConnectionRequired") || previous.SubjectHash is null || previous.SubjectHash != replacement.SubjectHash)
                throw new UnauthorizedAccessException("A current provider-verified replacement for the same identity is required.");
            previous.Status = "Superseded"; previous.ProtectedCredentials = ""; previous.ProtectedInventory = ""; previous.SubjectHash = null;
            previous.GrantedScopeSetsJson = "[]"; previous.LeaseOwner = null; previous.LeaseUntil = null;
        }
        // A terminal revoked record stays revoked; this receipt does not claim new erasure or
        // backup deletion. Bind it to exactly this fresh replacement in the same transaction.
        previous.Revision++; replacement.Revision++;
        db.Event(deployment.Id, recovered ? RecoveredEvent : RetiredEvent, previous.Id, previous.Revision, now, target: replacementId.ToString("D"));
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return new(previous.Id, previous.Status, previous.Revision, []);
    }

    private async Task RequireExpiredUnverifiedRecovery(ManagedConnection previous, ManagedConnection replacement, AgentManifest manifest, CancellationToken ct)
    {
        if (previous.RevokedAt is null || previous.ProtectedCredentials.Length != 0 || previous.ProtectedInventory.Length != 0 ||
            previous.SubjectHash is not null || previous.InventoryVerifiedAt is not null || Values(previous.GrantedScopeSetsJson).Length != 0 ||
            previous.LeaseOwner is not null || previous.LeaseUntil is not null || previous.ProfileRevision != replacement.ProfileRevision ||
            previous.PackageDigest != replacement.PackageDigest) throw new UnauthorizedAccessException();
        if (!await db.Events.AnyAsync(x => x.ConnectionId == previous.Id && x.DeploymentId == previous.DeploymentId && x.Kind == "connection.unclaimed-fenced", ct) ||
            !await db.Events.AnyAsync(x => x.ConnectionId == previous.Id && x.DeploymentId == previous.DeploymentId && x.Kind == "connection.provider-revoked-primary-erased", ct) ||
            await db.Events.AnyAsync(x => x.ConnectionId == previous.Id && (x.Kind == "connection.ready" || x.Kind == "connection.discovery-progress"), ct))
            throw new UnauthorizedAccessException();
        var original = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.ConnectionId == previous.Id && x.DeploymentId == previous.DeploymentId, ct)
            ?? throw new UnauthorizedAccessException();
        var fresh = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.ConnectionId == replacement.Id && x.DeploymentId == replacement.DeploymentId, ct)
            ?? throw new UnauthorizedAccessException();
        if (!original.Redeemed || original.Status != "Expired" || original.ExpiresAt.AddHours(1) > clock.GetUtcNow() ||
            !fresh.Redeemed || fresh.Status is not ("AuthorizedPendingDiscovery" or "Expired") ||
            original.InstallationId != previous.InstallationId || fresh.InstallationId != replacement.InstallationId ||
            string.IsNullOrWhiteSpace(original.ActorId) || original.ActorId != fresh.ActorId || original.PackageDigest != previous.PackageDigest || fresh.PackageDigest != replacement.PackageDigest ||
            original.DeclarationId != fresh.DeclarationId || fresh.DeclarationId != manifest.Accounts!.Connection ||
            original.PolicyVersion != fresh.PolicyVersion || fresh.PolicyVersion != manifest.Accounts.PolicyVersion ||
            !SameScopes(original.ScopeSetIdsJson, fresh.ScopeSetIdsJson) || !SameScopes(fresh.ScopeSetIdsJson, replacement.GrantedScopeSetsJson))
            throw new UnauthorizedAccessException();
        // Consent must begin after confirmed old revocation, so the shared provider grant is
        // never deliberately revoked underneath an already-consented replacement.
        var started = await db.Events.AsNoTracking().Where(x => x.SessionId == fresh.Id && x.DeploymentId == fresh.DeploymentId && x.Kind == "consent.started")
            .Select(x => x.CreatedAt).ToArrayAsync(ct);
        if (started.Length != 1 || started[0] < previous.RevokedAt) throw new UnauthorizedAccessException();
    }

    private static bool SameScopes(string left, string right)
    {
        var a = JsonSerializer.Deserialize<string[]>(left); var b = JsonSerializer.Deserialize<string[]>(right);
        return a is { Length: > 0 and <= 32 } && b is { Length: > 0 and <= 32 } &&
            !a.Concat(b).Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 128 || x.Any(char.IsControl)) &&
            a.Distinct(StringComparer.Ordinal).Count() == a.Length && b.Distinct(StringComparer.Ordinal).Count() == b.Length &&
            a.ToHashSet(StringComparer.Ordinal).SetEquals(b);
    }
}
