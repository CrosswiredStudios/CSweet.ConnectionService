using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Durable expiration and replay-record cleanup, never an OAuth code retry or fake revocation receipt.</summary>
public sealed class ConnectionMaintenance(IServiceScopeFactory scopes, TimeProvider clock) : BackgroundService
{
    public static async Task Sweep(ConnectionStore db, DateTimeOffset now, CancellationToken ct)
    {
        await db.Nonces.Where(x => x.ExpiresAt < now.ToUnixTimeSeconds() - 60).ExecuteDeleteAsync(ct);
        var sessions = await db.Sessions.Where(x => x.Status == "Created" || x.Status == "AwaitingConsent" || x.Status == "Exchanging").Take(1000).ToArrayAsync(ct);
        foreach (var session in sessions.Where(x => x.ExpiresAt <= now))
        {
            session.Status = session.Status == "Exchanging" ? "AuthorizationUncertain" : "Expired";
            session.FailureCode = session.Status == "AuthorizationUncertain" ? "authorization_outcome_unknown" : "consent_expired";
            session.ProtectedLaunch = ""; session.ProtectedVerifier = ""; session.BrowserHash = ""; session.StateHash = ""; session.Revision++;
            db.Event(session.DeploymentId, "consent.expired", null, session.Revision, now, session.Id);
        }
        await db.SaveChangesAsync(ct);
        var unclaimed = await db.Sessions.Where(x => x.ConnectionId != null && x.Status == "AuthorizedPendingDiscovery").Take(1000).ToArrayAsync(ct);
        foreach (var session in unclaimed.Where(x => !x.Redeemed && x.HandoffExpiresAt <= now || x.ExpiresAt.AddHours(1) <= now))
        {
            var connection = await db.Connections.SingleAsync(x => x.Id == session.ConnectionId, ct);
            if (connection.Status == "AuthorizedPendingDiscovery")
            { connection.Status = "RevocationPending"; connection.Revision++; db.Event(connection.DeploymentId, "connection.unclaimed-fenced", connection.Id, connection.Revision, now); }
            session.Status = "Expired"; session.ProtectedHandoff = null; session.HandoffHash = null; session.Revision++;
        }
        await db.SaveChangesAsync(ct);
        var retainedHandoffs = await db.Sessions.Where(x => x.ProtectedHandoff != null).Take(1000).ToArrayAsync(ct);
        foreach (var session in retainedHandoffs.Where(x => x.HandoffExpiresAt <= now))
        {
            session.ProtectedHandoff = null; session.HandoffHash = null; session.HandoffExpiresAt = null; session.Revision++;
        }
        await db.SaveChangesAsync(ct);
        foreach (var connection in await db.Connections.Where(x => x.Status == "Refreshing").ToArrayAsync(ct))
            if (connection.LeaseUntil <= now)
            {
                connection.Status = "ConnectionRequired"; connection.FailureCode = "refresh_outcome_requires_reauthorization";
                connection.LeaseOwner = null; connection.LeaseUntil = null; connection.Revision++;
                db.Event(connection.DeploymentId, "connection.reauthorization-required", connection.Id, connection.Revision, now);
            }
        await db.SaveChangesAsync(ct);
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30), clock);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await using var scope = scopes.CreateAsyncScope();
            try
            {
                await Sweep(scope.ServiceProvider.GetRequiredService<ConnectionStore>(), clock.GetUtcNow(), stoppingToken);
                await scope.ServiceProvider.GetRequiredService<ConnectionRevocationService>().Process(stoppingToken);
            }
            catch (DbUpdateException) { /* Another worker won the version fence; a later bounded pass retries. */ }
        }
    }
}
