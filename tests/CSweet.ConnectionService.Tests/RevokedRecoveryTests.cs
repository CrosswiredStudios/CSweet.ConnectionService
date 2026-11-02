using System.Net;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Data.Sqlite;

namespace CSweet.ConnectionService.Tests;

public sealed class RevokedRecoveryTests
{
    [Fact]
    public async Task FreshConsentLinksOnlyExpiredNeverDiscoveredRevocationWithoutRestoringOrRevokingCredentials()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        var replacementBefore = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.New));
        var oldBefore = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.Old));
        var counts = (f.Provider.Exchanges, f.Provider.Refreshes, f.Provider.Revocations, f.Api.Calls);
        var receipt = await f.Client().Supersede(pair.Old, pair.New);
        Assert.Equal("Revoked", receipt.Status); Assert.Empty(receipt.GrantedScopeSets);
        var old = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.Old));
        Assert.Equal("Revoked", old.Status); Assert.Equal(oldBefore.RevokedAt, old.RevokedAt);
        Assert.Empty(old.ProtectedCredentials); Assert.Empty(old.ProtectedInventory); Assert.Null(old.SubjectHash);
        var replacement = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.New));
        Assert.Equal("Ready", replacement.Status); Assert.Equal(replacementBefore.ProtectedCredentials, replacement.ProtectedCredentials);
        Assert.Equal(replacementBefore.SubjectHash, replacement.SubjectHash);
        Assert.Equal(counts, (f.Provider.Exchanges, f.Provider.Refreshes, f.Provider.Revocations, f.Api.Calls));
        var link = Assert.Single(await f.Db(db => db.Events.Where(x => x.Kind == "connection.revoked-replacement-linked").ToArrayAsync()));
        Assert.Equal(pair.New.ToString("D"), link.Target); Assert.Equal(old.Revision, link.Revision);
        SameReceipt(receipt, await f.Client().Supersede(pair.Old, pair.New));
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.revoked-replacement-linked")));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(pair.Old));
    }

    [Fact]
    public async Task ReceiptCannotBeReplayedForAnotherReplacementAndSurvivesLaterDisconnectOfItsBoundReplacement()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        var receipt = await f.Client().Supersede(pair.Old, pair.New);
        var other = await Connect(f, pair.Request with { LocalAttemptId = Guid.NewGuid() }, discover: true);
        await Denied(() => f.Client().Supersede(pair.Old, other));
        await f.Client().Disconnect(pair.New);
        SameReceipt(receipt, await f.Client().Supersede(pair.Old, pair.New));
        Assert.Equal("RevocationPending", (await f.Client().Get(pair.New)).Status);
        Assert.Equal(1, f.Provider.Revocations); // Only the original expiry cleanup.
    }

    [Theory]
    [InlineData("old-active")]
    [InlineData("old-pending-revocation")]
    [InlineData("old-refreshing")]
    [InlineData("old-credentials-retained")]
    [InlineData("old-verified-history")]
    [InlineData("old-verified-timestamp")]
    [InlineData("old-partial-discovery")]
    [InlineData("no-expiry-event")]
    [InlineData("no-primary-erasure-event")]
    [InlineData("original-not-redeemed")]
    [InlineData("original-cancelled")]
    [InlineData("different-actor")]
    [InlineData("different-installation")]
    [InlineData("different-profile")]
    [InlineData("different-profile-revision")]
    [InlineData("different-package")]
    [InlineData("different-deployment")]
    [InlineData("different-scope")]
    [InlineData("different-policy")]
    [InlineData("different-declaration")]
    [InlineData("replacement-not-redeemed")]
    [InlineData("replacement-not-ready")]
    [InlineData("replacement-no-subject")]
    [InlineData("replacement-stale")]
    [InlineData("replacement-future")]
    [InlineData("replacement-live-lease")]
    [InlineData("replacement-started-before-revocation")]
    public async Task InvalidRecoveryDoesNotChangeEitherAuthorityOrEmitReceipt(string mutation)
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        await f.Db(async db =>
        {
            var old = await db.Connections.SingleAsync(x => x.Id == pair.Old); var next = await db.Connections.SingleAsync(x => x.Id == pair.New);
            var original = await db.Sessions.SingleAsync(x => x.ConnectionId == pair.Old); var fresh = await db.Sessions.SingleAsync(x => x.ConnectionId == pair.New);
            switch (mutation)
            {
                case "old-active": old.Status = "AuthorizedPendingDiscovery"; break;
                case "old-pending-revocation": old.Status = "RevocationPending"; break;
                case "old-refreshing": old.Status = "Refreshing"; break;
                case "old-credentials-retained": old.ProtectedCredentials = "inert-synthetic-retained-ciphertext"; break;
                case "old-verified-history": db.Event(old.DeploymentId, "connection.ready", old.Id, 1, f.Clock.GetUtcNow()); break;
                case "old-verified-timestamp": old.InventoryVerifiedAt = f.Clock.GetUtcNow().AddHours(-2); break;
                case "old-partial-discovery": db.Event(old.DeploymentId, "connection.discovery-progress", old.Id, 1, f.Clock.GetUtcNow()); break;
                case "no-expiry-event": db.Events.RemoveRange(await db.Events.Where(x => x.ConnectionId == old.Id && x.Kind == "connection.unclaimed-fenced").ToArrayAsync()); break;
                case "no-primary-erasure-event": db.Events.RemoveRange(await db.Events.Where(x => x.ConnectionId == old.Id && x.Kind == "connection.provider-revoked-primary-erased").ToArrayAsync()); break;
                case "original-not-redeemed": original.Redeemed = false; break;
                case "original-cancelled": original.Status = "Cancelled"; break;
                case "different-actor": fresh.ActorId = "another-synthetic-human"; break;
                case "different-installation": next.InstallationId = Guid.NewGuid(); break;
                case "different-profile": next.ProfileId = "different-profile"; break;
                case "different-profile-revision": next.ProfileRevision++; break;
                case "different-package": old.PackageDigest = new string('b', 64); break;
                case "different-deployment": next.DeploymentId = Guid.NewGuid(); break;
                case "different-scope": fresh.ScopeSetIdsJson = next.GrantedScopeSetsJson = "[\"base\",\"upload\"]"; break;
                case "different-policy": fresh.PolicyVersion = "different-policy"; break;
                case "different-declaration": fresh.DeclarationId = "different-declaration"; break;
                case "replacement-not-redeemed": fresh.Redeemed = false; break;
                case "replacement-not-ready": next.Status = "AuthorizedPendingDiscovery"; break;
                case "replacement-no-subject": next.SubjectHash = null; break;
                case "replacement-stale": next.InventoryVerifiedAt = f.Clock.GetUtcNow().AddHours(-2); break;
                case "replacement-future": next.InventoryVerifiedAt = f.Clock.GetUtcNow().AddHours(1); break;
                case "replacement-live-lease": next.LeaseOwner = Guid.NewGuid(); next.LeaseUntil = f.Clock.GetUtcNow().AddMinutes(1); break;
                case "replacement-started-before-revocation": (await db.Events.SingleAsync(x => x.SessionId == fresh.Id && x.Kind == "consent.started")).CreatedAt = old.RevokedAt!.Value.AddSeconds(-1); break;
            }
            await db.SaveChangesAsync(); return true;
        });
        var revisions = await f.Db(async db => (Old: (await db.Connections.SingleAsync(x => x.Id == pair.Old)).Revision, New: (await db.Connections.SingleAsync(x => x.Id == pair.New)).Revision));
        await Denied(() => f.Client().Supersede(pair.Old, pair.New));
        Assert.Equal(revisions, await f.Db(async db => (Old: (await db.Connections.SingleAsync(x => x.Id == pair.Old)).Revision, New: (await db.Connections.SingleAsync(x => x.Id == pair.New)).Revision)));
        Assert.Equal(0, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.revoked-replacement-linked")));
        Assert.Equal(1, f.Provider.Revocations);
    }

    [Fact]
    public async Task FailureRollsBackReceiptAndBothRevisionFencesAndDoesNotDestroyReplacement()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        var before = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.New));
        f.Saves.Fail = true;
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Supersede(pair.Old, pair.New));
        Assert.Equal(HttpStatusCode.Conflict, error.StatusCode);
        Assert.Equal(0, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.revoked-replacement-linked")));
        var after = await f.Db(db => db.Connections.AsNoTracking().SingleAsync(x => x.Id == pair.New));
        Assert.Equal(before.Revision, after.Revision); Assert.Equal(before.ProtectedCredentials, after.ProtectedCredentials);
        f.Saves.Fail = false; Assert.Equal("Revoked", (await f.Client().Supersede(pair.Old, pair.New)).Status);
    }

    [Fact]
    public async Task ConcurrentReplacementFenceCannotSlipBetweenValidationAndAtomicReceiptSave()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        f.Saves.BeforeSave = () =>
        {
            using var other = new SqliteConnection("Data Source=" + Path.Combine(f.Root, "connections.db") + ";Default Timeout=1"); other.Open();
            using var command = other.CreateCommand(); command.CommandText = "UPDATE Connections SET Status='RevocationPending', Revision=Revision+1 WHERE Id=$id";
            command.Parameters.AddWithValue("$id", pair.New); var error = Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
            Assert.Contains(error.SqliteErrorCode, new[] { 5, 6 }); f.Saves.ConcurrentWriterBlocked = true;
        };
        Assert.Equal("Revoked", (await f.Client().Supersede(pair.Old, pair.New)).Status);
        Assert.True(f.Saves.ConcurrentWriterBlocked); Assert.Equal("Ready", (await f.Client().Get(pair.New)).Status);
        Assert.Equal(1, f.Provider.Revocations);
    }

    [Fact]
    public async Task AlreadyFencedReplacementAndWrongDeploymentCannotAcknowledgeRecovery()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        using var otherKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var wrongDeployment = new ManagedConnectionClient(f.Http, new(ServiceFixture.Origin), Guid.NewGuid(), "key-1", 1, otherKey, f.Clock);
        await Denied(() => wrongDeployment.Supersede(pair.Old, pair.New));
        await f.Client().Disconnect(pair.New);
        await Denied(() => f.Client().Supersede(pair.Old, pair.New));
        Assert.Equal(0, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.revoked-replacement-linked")));
    }

    [Fact]
    public async Task ConcurrentDuplicateRequestsProduceOneDurableBoundReceipt()
    {
        await using var f = new Fixture(); var pair = await Prepare(f);
        var replies = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => f.Client().Supersede(pair.Old, pair.New)));
        Assert.All(replies, reply => SameReceipt(replies[0], reply));
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.revoked-replacement-linked")));
        Assert.Equal(1, f.Provider.Revocations);
    }

    private static async Task Denied(Func<Task<ConnectionSnapshot>> action) =>
        Assert.Equal(HttpStatusCode.Forbidden, (await Assert.ThrowsAsync<HttpRequestException>(action)).StatusCode);
    private static void SameReceipt(ConnectionSnapshot expected, ConnectionSnapshot actual)
    {
        Assert.Equal((expected.ConnectionId, expected.Status, expected.Revision), (actual.ConnectionId, actual.Status, actual.Revision));
        Assert.Equal(expected.GrantedScopeSets, actual.GrantedScopeSets);
    }
    private static async Task<Guid> Connect(Fixture f, BeginConnection request, bool discover)
    {
        var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, request.PackageDigest));
        if (discover) await f.Client().Discover(receipt.ConnectionId!.Value);
        return receipt.ConnectionId!.Value;
    }
    private static async Task<(Guid Old, Guid New, BeginConnection Request)> Prepare(Fixture f)
    {
        await f.Initialize(); var request = f.BeginRequest(); var old = await Connect(f, request, discover: false);
        f.Clock.Advance(TimeSpan.FromMinutes(71));
        await f.Db(async db => { await ConnectionMaintenance.Sweep(db, f.Clock.GetUtcNow(), default); return true; });
        await using (var scope = f.Services.CreateAsyncScope()) await scope.ServiceProvider.GetRequiredService<ConnectionRevocationService>().Process(default);
        Assert.Equal("Revoked", (await f.Client().Get(old)).Status); Assert.Equal(1, f.Provider.Revocations);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); var replacement = await Connect(f, request with { LocalAttemptId = Guid.NewGuid() }, discover: true);
        return (old, replacement, request);
    }
    private sealed class Fixture : ServiceFixture
    {
        internal readonly Api Api = new(); internal readonly SaveHook Saves = new();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder); builder.ConfigureServices(services => {
                services.RemoveAll<IProviderApiTransport>(); services.AddSingleton<IProviderApiTransport>(Api);
                services.AddDbContext<ConnectionStore>(o => o.AddInterceptors(Saves));
            });
        }
    }
    private sealed class Api : IProviderApiTransport
    {
        internal int Calls;
        public Task<JsonElement> Read(Uri destination, string token, CancellationToken ct)
        {
            Calls++; return Task.FromResult(destination.AbsolutePath.Contains("userinfo", StringComparison.Ordinal)
                ? JsonSerializer.SerializeToElement(new { sub = "synthetic-subject", name = "Synthetic account" })
                : JsonSerializer.SerializeToElement(new { items = new[] { new { id = "synthetic-channel", snippet = new { title = "Synthetic channel" } } } }));
        }
    }
    private sealed class SaveHook : SaveChangesInterceptor
    {
        internal bool Fail, ConcurrentWriterBlocked; internal Action? BeforeSave;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData data, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (data.Context!.ChangeTracker.Entries<ConnectionEvent>().Any(x => x.State == EntityState.Added && x.Entity.Kind == "connection.revoked-replacement-linked"))
            { BeforeSave?.Invoke(); if (Fail) throw new DbUpdateException("Synthetic receipt rollback"); }
            return ValueTask.FromResult(result);
        }
    }
}
