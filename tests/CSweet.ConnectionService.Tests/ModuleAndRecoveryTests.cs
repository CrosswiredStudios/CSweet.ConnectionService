using System.Net.Http.Json;
using System.Text.Json;
using CSweet.ConnectionService.Core;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Tests;

public sealed class ModuleAndRecoveryTests
{
    [Fact]
    public async Task CoreHostsAnIndependentNonOAuthModuleWithoutProviderChanges()
    {
        await using var f = new ModuleFixture(); await f.Initialize();
        var features = await f.Http.GetFromJsonAsync<JsonElement>("/features");
        Assert.Contains(features.EnumerateArray(), x => x.GetProperty("kind").GetString() == "oauth");
        Assert.Contains(features.EnumerateArray(), x => x.GetProperty("kind").GetString() == "device-link-test");
        Assert.Equal("test-only", await f.Http.GetStringAsync("/test-module/description"));
    }
    [Fact]
    public async Task RedeemedReceiptRecoveryRequiresOriginalProofAndDoesNotReplayHandoff()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest();
        var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        var redeemed = await f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        var request = new RecoverConnection(begin.LocalAttemptId, begin.ActorId, f.Digest, f.ReturnVerifier);
        var recovered = await f.Client().Recover(redeemed.SessionId, request);
        Assert.Equal(redeemed.SessionId, recovered.SessionId); Assert.Equal(redeemed.ConnectionId, recovered.ConnectionId);
        Assert.Equal(redeemed.Status, recovered.Status); Assert.Equal(redeemed.GrantedScopeSets, recovered.GrantedScopeSets);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Recover(redeemed.SessionId, request with { ReturnVerifier = DeploymentProofCodec.Random() }));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest)));
        Assert.Equal(1, f.Provider.Exchanges);
    }
    [Fact]
    public async Task CancellingAnAwaitingAttemptMakesItsLaunchAndCallbackUnusable()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (attempt, state, cookie) = await f.Launch();
        var result = await f.Client().Cancel(attempt.SessionId); Assert.Equal("Cancelled", result.Status); Assert.Null(result.ConnectionId);
        using var message = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?code=unused&state=" + Uri.EscapeDataString(state));
        message.Headers.Add("Cookie", cookie);
        using var response = await f.Http.SendAsync(message); Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, f.Provider.Exchanges);
    }
    [Fact]
    public async Task CancellationByOriginalAttemptRecoversLostBeginResponsesAndFencesLateCreation()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        var request = f.BeginRequest(); var remote = await f.Client().Begin(request);
        var cancelled = await f.Client().CancelAttempt(request.LocalAttemptId);
        Assert.Equal(remote.SessionId, cancelled.SessionId); Assert.Equal("Cancelled", cancelled.Status);
        var neverStarted = f.BeginRequest();
        var tombstone = await f.Client().CancelAttempt(neverStarted.LocalAttemptId);
        Assert.Equal("Cancelled", tombstone.Status);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(neverStarted));
        Assert.Equal(tombstone.SessionId, (await f.Client().CancelAttempt(neverStarted.LocalAttemptId)).SessionId);
        Assert.Equal(0, f.Provider.Exchanges);
    }
    [Fact]
    public async Task CancellationDuringProviderExchangeCannotRestoreItsConnectionAuthority()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (attempt, state, cookie) = await f.Launch();
        f.Provider.BeforeReceipt = async () => { await f.Client().Cancel(attempt.SessionId); };
        await f.Callback(state, cookie);
        Assert.Equal("RevocationPending", (await f.Db(db => db.Connections.SingleAsync())).Status);
        Assert.Equal("Failed", (await f.Db(db => db.Sessions.SingleAsync())).Status); Assert.Equal(1, f.Provider.Exchanges);
    }
    [Fact]
    public async Task DeniedConsentAlsoErasesExpiredHandoffMaterial()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (_, state, cookie) = await f.Launch();
        await f.Callback(state, cookie, "access_denied"); f.Clock.Advance(TimeSpan.FromMinutes(3));
        await f.Db(async db => { await ConnectionMaintenance.Sweep(db, f.Clock.GetUtcNow(), default); return true; });
        var session = await f.Db(db => db.Sessions.SingleAsync());
        Assert.Null(session.ProtectedHandoff); Assert.Null(session.HandoffHash); Assert.Null(session.HandoffExpiresAt);
        Assert.Empty(session.ProtectedVerifier); Assert.Empty(await f.Db(db => db.Connections.ToArrayAsync()));
    }
    [Fact]
    public async Task SchemaUpgradeIsRepeatableAndPreservesEncryptedCredentials()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var request = f.BeginRequest();
        var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        var before = await f.Db(db => db.Connections.Select(x => x.ProtectedCredentials).SingleAsync());
        await using var scope = f.Services.CreateAsyncScope(); var db = scope.ServiceProvider.GetRequiredService<ConnectionStore>();
        await ConnectionSchema.Upgrade(db); await ConnectionSchema.Upgrade(db); await ConnectionSchema.RequireCurrent(db);
        Assert.Equal(before, await db.Connections.Select(x => x.ProtectedCredentials).SingleAsync());
    }
    private sealed class ModuleFixture : ServiceFixture
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        { base.ConfigureWebHost(builder); builder.ConfigureServices(services => services.AddSingleton<IConnectionModule, DeviceTestModule>()); }
    }
    private sealed class DeviceTestModule : IConnectionModule
    {
        public string Kind => "device-link-test";
        public string Protocol => "test";
        public void MapEndpoints(IEndpointRouteBuilder endpoints) => endpoints.MapGet("/test-module/description", () => Results.Text("test-only"));
    }
}
