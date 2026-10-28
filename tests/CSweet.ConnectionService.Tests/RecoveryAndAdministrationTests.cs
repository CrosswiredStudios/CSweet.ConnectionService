using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService.Tests;

public sealed class RecoveryAndAdministrationTests
{
    [Fact]
    public async Task BrowserRedirectResponsesUseSafeHeadersAndSecureHostCookies()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var attempt = await f.Client().Begin(f.BeginRequest());
        using var response = await f.Http.GetAsync(attempt.LaunchUrl);
        Assert.True(response.Headers.CacheControl!.NoStore); Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        var cookie = response.Headers.GetValues("Set-Cookie").Single();
        Assert.StartsWith("__Host-csweet-oauth-", cookie); Assert.Contains("secure", cookie); Assert.Contains("httponly", cookie); Assert.Contains("samesite=lax", cookie);
        Assert.DoesNotContain("domain=", cookie);
    }
    [Theory]
    [InlineData("deployment")]
    [InlineData("profile")]
    public async Task RevocationDuringExchangeCannotCreateAnActiveConnection(string target)
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        f.Provider.BeforeReceipt = async () =>
        {
            using var response = await f.Http.PostAsync(target == "deployment" ? $"/operator/deployments/{f.Deployment.DeploymentId}/revoke" : $"/operator/profiles/{f.ProfileId}/disable", null);
            response.EnsureSuccessStatusCode();
        };
        var (_, state, cookie) = await f.Launch(); await f.Callback(state, cookie);
        var connection = await f.Db(db => db.Connections.SingleAsync()); Assert.Equal("RevocationPending", connection.Status);
        Assert.Equal("Failed", (await f.Db(db => db.Sessions.SingleAsync())).Status);
    }
    [Fact]
    public async Task LogsNeverContainProofsProviderSecretsCodesStateOrHandoffs()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest(); var (attempt, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        await f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        var logs = string.Join('\n', f.Logs.Messages);
        foreach (var secret in new[] { "application-secret", "secret-access-token", "secret-refresh-token", "one-time-code", state, h, cookie.Split('=')[1], new Uri(attempt.LaunchUrl!).Segments.Last() })
            Assert.DoesNotContain(secret, logs);
    }
    [Fact]
    public async Task ConcurrentCallbacksProduceOnlyOneCredentialAndProviderExchange()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (_, state, cookie) = await f.Launch();
        async Task<HttpStatusCode> Callback()
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code"); request.Headers.Add("Cookie", cookie);
            using var response = await f.Http.SendAsync(request); return response.StatusCode;
        }
        var results = await Task.WhenAll(Callback(), Callback());
        Assert.Single(results, x => x == HttpStatusCode.Redirect); Assert.Single(results, x => x is HttpStatusCode.Forbidden or HttpStatusCode.Conflict);
        Assert.Equal(1, f.Provider.Exchanges); Assert.Equal(1, await f.Db(db => db.Connections.CountAsync()));
    }
    [Fact]
    public async Task ConsumedLaunchIsNotAnOAuthRetryButton()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var (attempt, _, _) = await f.Launch();
        using var response = await f.Http.GetAsync(attempt.LaunchUrl); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, f.Provider.Exchanges);
    }
    [Fact]
    public async Task ExpiredAttemptsAreDurablyClearedAndUnknownExchangesAreNotRetried()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var attempt = await f.Client().Begin(f.BeginRequest());
        f.Clock.Advance(TimeSpan.FromMinutes(11));
        await f.Db(async db => { await ConnectionMaintenance.Sweep(db, f.Clock.GetUtcNow(), default); return 0; });
        var session = await f.Db(db => db.Sessions.SingleAsync(x => x.Id == attempt.SessionId));
        Assert.Equal("Expired", session.Status); Assert.Empty(session.ProtectedLaunch); Assert.Empty(session.ProtectedVerifier);
        await f.Db(async db => { var row = await db.Sessions.SingleAsync(); row.Status = "Exchanging"; await db.SaveChangesAsync(); return 0; });
        await f.Db(async db => { await ConnectionMaintenance.Sweep(db, f.Clock.GetUtcNow(), default); return 0; });
        Assert.Equal("AuthorizationUncertain", (await f.Db(db => db.Sessions.SingleAsync())).Status); Assert.Equal(0, f.Provider.Exchanges);
    }
    [Fact]
    public async Task SecretRotationDoesNotChangePublicProfileIdentityOrApprovalBindings()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var before = await f.Client().Availability(f.Digest);
        var profile = await f.Db(db => db.Profiles.SingleAsync());
        using var response = await f.Http.PutAsJsonAsync("/operator/profiles", new ConfigureProvider(profile.Id, profile.ClientId, profile.AuthorizationEndpoint, profile.TokenEndpoint, profile.RevocationEndpoint, "rotated-secret")); response.EnsureSuccessStatusCode();
        Assert.Equal(before, await f.Client().Availability(f.Digest));
        var updated = await f.Db(db => db.Profiles.SingleAsync()); Assert.Equal(2, updated.SecretVersion); Assert.Equal(1, updated.Revision); Assert.DoesNotContain("rotated-secret", updated.ProtectedSecret);
        using var changed = await f.Http.PutAsJsonAsync("/operator/profiles", new ConfigureProvider(profile.Id, "different-client", profile.AuthorizationEndpoint, profile.TokenEndpoint, profile.RevocationEndpoint, "another-secret"));
        Assert.Equal(HttpStatusCode.BadRequest, changed.StatusCode);
    }
    [Fact]
    public async Task DisabledProfileBlocksLaunchAndCannotRestoreItselfThroughSecretUpdate()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var attempt = await f.Client().Begin(f.BeginRequest());
        using var disable = await f.Http.PostAsync("/operator/profiles/" + f.ProfileId + "/disable", null); disable.EnsureSuccessStatusCode();
        using var launch = await f.Http.GetAsync(attempt.LaunchUrl); Assert.Equal(HttpStatusCode.Forbidden, launch.StatusCode);
        var profile = await f.Db(db => db.Profiles.SingleAsync());
        using var restore = await f.Http.PutAsJsonAsync("/operator/profiles", new ConfigureProvider(profile.Id, profile.ClientId, profile.AuthorizationEndpoint, profile.TokenEndpoint, profile.RevocationEndpoint, "application-secret"));
        Assert.Equal(HttpStatusCode.BadRequest, restore.StatusCode);
    }
    [Fact]
    public async Task ActiveAttemptCannotBeRetargetedByReplacingAnApprovedDigest()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        var changed = f.Manifest.Replace("\"name\": \"YouTube\"", "\"name\": \"A different package\"", StringComparison.Ordinal);
        Assert.NotEqual(f.Manifest, changed);
        using var response = await f.Http.PostAsJsonAsync("/operator/packages", new ApprovePackage(f.Digest, DeploymentProofCodec.Hash(changed), changed, f.ProfileId, 1, "https://github.com/example/connector", new string('a', 40)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
    [Fact]
    public async Task OversizedRequestsAreRejectedWithoutProcessingCredentials()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); using var request = f.Signed("/v1/sessions", f.BeginRequest());
        request.Content = new ByteArrayContent(new byte[ConnectionProtocol.MaximumBodyBytes + 1]);
        using var response = await f.Http.SendAsync(request); Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode); Assert.Equal(0, f.Provider.Exchanges);
    }
}
