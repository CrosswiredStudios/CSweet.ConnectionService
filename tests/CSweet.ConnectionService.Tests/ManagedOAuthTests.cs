using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedOAuthTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReviewedProvidersUseTheSameSecureFlowWithoutExposingTokens(bool secondProvider)
    {
        await using var f = new ServiceFixture(); await f.Initialize(secondProvider);
        var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var handoff = await f.Callback(state, cookie);
        var result = await f.Client().Redeem(new(handoff, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        Assert.Equal("AuthorizedPendingDiscovery", result.Status); Assert.Equal(new[] { "base" }, result.GrantedScopeSets); Assert.NotNull(result.ConnectionId);
        var snapshot = await f.Client().Get(result.ConnectionId.Value);
        Assert.Equal("AuthorizedPendingDiscovery", snapshot.Status); Assert.Equal(1, f.Provider.Exchanges);
        var serialized = JsonSerializer.Serialize(result) + JsonSerializer.Serialize(snapshot) + JsonSerializer.Serialize(await f.Client().Events(0));
        Assert.DoesNotContain("secret-access-token", serialized); Assert.DoesNotContain("secret-refresh-token", serialized); Assert.DoesNotContain("application-secret", serialized);
        var stored = await f.Db(db => db.Connections.SingleAsync());
        Assert.DoesNotContain("secret-access-token", stored.ProtectedCredentials);
        var events = await f.Client().Events(0); Assert.Contains(events, e => e.Kind == "consent.redeemed" && e.SessionId == result.SessionId);
        var disconnected = await f.Client().Disconnect(result.ConnectionId.Value);
        Assert.Equal("RevocationPending", disconnected.Status); Assert.Empty(disconnected.GrantedScopeSets);
        var repeated = await f.Client().Disconnect(result.ConnectionId.Value);
        Assert.Equal(disconnected.ConnectionId, repeated.ConnectionId); Assert.Equal(disconnected.Revision, repeated.Revision); Assert.Equal(disconnected.Status, repeated.Status);
        Assert.NotEmpty((await f.Db(db => db.Connections.SingleAsync())).ProtectedCredentials); // Pending is not confirmed provider revocation/purge.
    }
    [Fact]
    public async Task IdempotentBeginReturnsTheSameAttemptButRejectsChangedChoices()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var request = f.BeginRequest();
        var first = await f.Client().Begin(request); Assert.Equal(first, await f.Client().Begin(request));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(request with { ActorId = "another-human" }));
        Assert.Equal(1, await f.Db(db => db.Sessions.CountAsync()));
    }
    [Fact]
    public async Task OptionalConsentCanBeDeclinedAndExtraScopesNeverBecomeAuthority()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        using var manifest = JsonDocument.Parse(f.Manifest);
        f.Provider.GrantedScopes = manifest.RootElement.GetProperty("connections")[0].GetProperty("scopeSets")[0].GetProperty("scopes").EnumerateArray().Select(x => x.GetString()!).Append("https://unrequested.example/scope").ToArray();
        var request = f.BeginRequest(["base", "publishing"]); var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie);
        var result = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        Assert.Equal(new[] { "base" }, result.GrantedScopeSets); Assert.Equal("AuthorizedPendingDiscovery", result.Status);
    }
    [Fact]
    public async Task MissingRequiredAccessFencesCredentialsAndNeverPretendsDeletionFinished()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); f.Provider.GrantedScopes = ["openid"];
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie);
        var result = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        Assert.Equal("Failed", result.Status); Assert.Equal("required_permission_missing", result.FailureCode); Assert.Empty(result.GrantedScopeSets);
        Assert.Equal("RevocationPending", (await f.Client().Get(result.ConnectionId!.Value)).Status);
    }
    [Fact]
    public async Task DenialHasASingleUseFailureHandoffWithoutTokenExchange()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var request = f.BeginRequest();
        var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie, "access_denied");
        var result = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        Assert.Equal("Cancelled", result.Status); Assert.Null(result.ConnectionId); Assert.Equal(0, f.Provider.Exchanges);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest)));
    }
    [Fact]
    public async Task MissingBrowserBindingAndWrongProfileCannotExchangeACode()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (_, state, _) = await f.Launch();
        using var response = await f.Http.GetAsync("/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, f.Provider.Exchanges);
        using var other = await f.Http.GetAsync("/oauth/callback/another.profile?state=" + Uri.EscapeDataString(state) + "&code=one-time-code");
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
    }
    [Fact]
    public async Task CallbackReplayNeverExchangesTheSameCodeTwice()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (_, state, cookie) = await f.Launch(); await f.Callback(state, cookie);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code"); request.Headers.Add("Cookie", cookie);
        using var response = await f.Http.SendAsync(request); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(1, f.Provider.Exchanges);
    }
    [Fact]
    public async Task HandoffRequiresTheOriginalVerifierActorAndLocalAttempt()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        var good = new RedeemConnection(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(good with { ReturnVerifier = DeploymentProofCodec.Random() }));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(good with { ActorId = "another-human" }));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(good with { LocalAttemptId = Guid.NewGuid() }));
        Assert.NotNull((await f.Client().Redeem(good)).ConnectionId);
    }
    [Fact]
    public async Task ExpiredHandoffCannotBeRedeemed()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        f.Clock.Advance(TimeSpan.FromMinutes(3));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest)));
    }
    [Fact]
    public async Task UnregisteredReturnAndUndeclaredScopesNeverCreateAnAttempt()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest() with { ReturnUri = "https://evil.example/return" }));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest(["partner"])));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest() with { AcceptPolicies = false }));
        Assert.Equal(0, await f.Db(db => db.Sessions.CountAsync()));
    }
    [Fact]
    public async Task ProviderFailureIsSanitizedAndCodeIsNotRetried()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); f.Provider.Fail = true;
        var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        var result = await f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        Assert.Equal("provider_authorization_failed", result.FailureCode); Assert.DoesNotContain("SECRET", JsonSerializer.Serialize(result)); Assert.Equal(1, f.Provider.Exchanges);
    }
    [Fact]
    public async Task PendingConsentSurvivesANewServiceInstanceWithTheSameDurableKeys()
    {
        var first = new ServiceFixture(); await first.Initialize(); var begin = first.BeginRequest(); var (_, state, cookie) = await first.Launch(begin);
        await using var next = new ServiceFixture(first.Root) { Deployment = first.Deployment, Manifest = first.Manifest, Digest = first.Digest, ReturnVerifier = first.ReturnVerifier, ProfileId = first.ProfileId };
        next.DeploymentKey.ImportPkcs8PrivateKey(first.DeploymentKey.ExportPkcs8PrivateKey(), out _); next.Provider.ExpectedChallenge = first.Provider.ExpectedChallenge;
        await first.DisposeAsync(); next.Http = next.NewClient();
        var h = await next.Callback(state, cookie);
        var result = await next.Client().Redeem(new(h, next.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, next.Digest));
        Assert.Equal("AuthorizedPendingDiscovery", result.Status); Assert.Equal(1, next.Provider.Exchanges);
    }
}
