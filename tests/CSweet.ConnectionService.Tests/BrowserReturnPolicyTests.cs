using System.Net;
using System.Net.Http.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Tests;

public sealed class BrowserReturnPolicyTests
{
    private const string LocalReturn = "https://localhost:7125/settings/plugins/managed-return";
    private static ServiceOptions Options(params string[] allowed) => new()
    {
        PublicOrigin = ServiceFixture.Origin, Database = "Data Source=:memory:", KeyRingDirectory = "/synthetic/keys",
        ProtectionCertificatePath = "/synthetic/not-read.pfx", AllowedLocalBrowserReturnUris = allowed
    };

    [Fact]
    public void LocalBrowserReturnsAreDisabledByDefaultAndDoNotWeakenPublicGuards()
    {
        var options = Options(); options.Validate(false);
        Assert.Empty(options.AllowedLocalBrowserReturnUris);
        Assert.Throws<ArgumentException>(() => options.ValidateReturn(LocalReturn));
        options.AllowedLocalBrowserReturnUris = [LocalReturn]; options.Validate(false); options.ValidateReturn(LocalReturn);
        Assert.Throws<ArgumentException>(() => Guards.Https(LocalReturn));
        options.PublicOrigin = "https://localhost";
        Assert.Throws<ArgumentException>(() => options.Validate(false));
        Options().ValidateReturn(ServiceFixture.ReturnUri);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void LegacyUnrestrictedLoopbackSwitchFailsClosed(bool development)
    {
        var options = Options(LocalReturn); options.AllowDevelopmentLoopbackReturns = true;
        Assert.Throws<InvalidOperationException>(() => options.Validate(development));
        Assert.Throws<ArgumentException>(() => options.ValidateReturn("http://localhost:7125/settings/plugins/managed-return"));
    }

    [Theory]
    [InlineData(LocalReturn)]
    [InlineData("https://127.0.0.1:7125/settings/plugins/managed-return")]
    [InlineData("https://[::1]:7125/settings/plugins/managed-return")]
    public void OnlyExplicitCanonicalLocalAddressesAreAccepted(string value)
    {
        var options = Options(value); options.Validate(false); options.ValidateReturn(value);
    }

    public static IEnumerable<object[]> ChangedLocalReturns() => new[]
    {
        "http://localhost:7125/settings/plugins/managed-return", "https://127.0.0.1:7125/settings/plugins/managed-return",
        "https://[::1]:7125/settings/plugins/managed-return", "https://localhost:7126/settings/plugins/managed-return",
        "https://localhost/settings/plugins/managed-return", "https://localhost:7125/settings/plugins/other",
        "https://localhost:7125/settings/plugins/managed-return/", "https://localhost:7125/Settings/plugins/managed-return",
        "https://user@localhost:7125/settings/plugins/managed-return", "https://user:password@localhost:7125/settings/plugins/managed-return",
        LocalReturn + "?next=other", LocalReturn + "?", LocalReturn + "#handoff=forged", LocalReturn + "#",
        "https://localhost:7125/settings/plugins/%6danaged-return", "https://localhost:7125/settings%2fplugins/managed-return",
        "https://localhost:7125/x/../settings/plugins/managed-return", "https://localhost:7125/%2e%2e/settings/plugins/managed-return",
        "https://LOCALHOST:7125/settings/plugins/managed-return", "https://localhost.:7125/settings/plugins/managed-return",
        "https://localhost:7125\\settings\\plugins\\managed-return", " " + LocalReturn, LocalReturn + " "
    }.Select(value => new object[] { value });

    [Theory]
    [MemberData(nameof(ChangedLocalReturns))]
    public void LocalReturnsRequireExactCanonicalMatching(string target) => Assert.Throws<ArgumentException>(() => Options(LocalReturn).ValidateReturn(target));

    [Theory]
    [InlineData("http://localhost:7125/settings/plugins/managed-return")]
    [InlineData("https://*.localhost:7125/settings/plugins/managed-return")]
    [InlineData("https://localhost:*/settings/plugins/managed-return")]
    [InlineData("https://localhost:0/settings/plugins/managed-return")]
    [InlineData("https://customer.example.com/return")]
    [InlineData("https://localhost:7125/settings/plugins/%6danaged-return")]
    [InlineData("https://localhost:7125/settings/plugins/managed-return?next=other")]
    [InlineData("https://localhost:7125/settings/plugins/managed-return#fragment")]
    [InlineData("https://user@localhost:7125/settings/plugins/managed-return")]
    public void InvalidOwnerAllowlistFailsAtStartup(string entry) => Assert.Throws<ArgumentException>(() => Options(entry).Validate(false));

    [Fact]
    public void AllowlistIsBoundedAndRejectsDuplicates()
    {
        Assert.Throws<ArgumentException>(() => Options(LocalReturn, LocalReturn).Validate(false));
        Assert.Throws<ArgumentException>(() => Options(Enumerable.Range(0, 21).Select(i => $"https://localhost:7125/return/{i}").ToArray()).Validate(false));
        var options = Options(); options.AllowedLocalBrowserReturnUris = null!;
        Assert.Throws<ArgumentException>(() => options.Validate(false));
    }

    [Fact]
    public async Task AllowlistDoesNotReplaceExactEnrollmentOrPermitAnyOutboundReturnProbe()
    {
        var outbound = new NoOutboundClients();
        await using var f = new ServiceFixture { EnrolledReturnUri = LocalReturn, LocalBrowserReturns = [LocalReturn], OutboundClients = outbound };
        await f.Initialize();
        foreach (var target in ChangedLocalReturns().Select(row => (string)row[0]).Append("https://localhost.attacker.example/settings/plugins/managed-return").Append(ServiceFixture.ReturnUri))
        {
            var error = await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest() with { ReturnUri = target }));
            Assert.True(error.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden);
        }
        Assert.Equal(0, await f.Db(db => db.Sessions.CountAsync()));
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request);
        using (var wrongBrowser = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code"))
        {
            wrongBrowser.Headers.Add("Cookie", cookie.Split('=')[0] + "=wrong-browser");
            using var denied = await f.Http.SendAsync(wrongBrowser); Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
        Assert.Equal(0, f.Provider.Exchanges);
        var handoff = await f.Callback(state, cookie);
        Assert.Equal(ServiceFixture.Origin + "/oauth/callback/" + f.ProfileId, f.Provider.LastCallback);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, f.ReturnVerifier, Guid.NewGuid(), request.ActorId, f.Digest)));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, "another-user", f.Digest)));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, DeploymentProofCodec.Random(), request.LocalAttemptId, request.ActorId, f.Digest)));
        var receipt = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        Assert.Equal("AuthorizedPendingDiscovery", receipt.Status);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest)));
        using var callbackReplay = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code");
        callbackReplay.Headers.Add("Cookie", cookie);
        using var replay = await f.Http.SendAsync(callbackReplay); Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
        Assert.Equal(1, f.Provider.Exchanges); Assert.Equal(0, outbound.Calls);
    }

    [Fact]
    public async Task LocalEnrollmentStillRequiresAnExplicitOwnerAllowlist()
    {
        await using var f = new ServiceFixture { EnrolledReturnUri = LocalReturn };
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Initialize());
        Assert.Equal(0, await f.Db(db => db.Deployments.CountAsync()));
    }

    [Fact]
    public async Task OwnerAllowlistDoesNotEnrollAnAddressForAnExistingDeployment()
    {
        await using var f = new ServiceFixture { LocalBrowserReturns = [LocalReturn] }; await f.Initialize();
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest() with { ReturnUri = LocalReturn }));
        Assert.Equal(HttpStatusCode.Forbidden, error.StatusCode);
        Assert.Equal(0, await f.Db(db => db.Sessions.CountAsync())); Assert.Equal(0, f.Provider.Exchanges);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RemovedLocalPermissionBlocksLaunchOrCallbackBeforeProviderExchange(bool afterLaunch)
    {
        await using var f = new ServiceFixture { EnrolledReturnUri = LocalReturn, LocalBrowserReturns = [LocalReturn] };
        await f.Initialize();
        if (afterLaunch)
        {
            var (_, state, cookie) = await f.Launch();
            f.Services.GetRequiredService<ServiceOptions>().AllowedLocalBrowserReturnUris = [];
            using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + f.ProfileId + "?state=" + Uri.EscapeDataString(state) + "&code=one-time-code");
            request.Headers.Add("Cookie", cookie);
            using var response = await f.Http.SendAsync(request); Assert.False(response.IsSuccessStatusCode); Assert.Null(response.Headers.Location);
            Assert.Equal("AwaitingConsent", await f.Db(db => db.Sessions.Select(s => s.Status).SingleAsync()));
        }
        else
        {
            var attempt = await f.Client().Begin(f.BeginRequest());
            f.Services.GetRequiredService<ServiceOptions>().AllowedLocalBrowserReturnUris = [];
            using var response = await f.Http.GetAsync(attempt.LaunchUrl); Assert.False(response.IsSuccessStatusCode); Assert.Null(response.Headers.Location);
            Assert.Equal("Created", await f.Db(db => db.Sessions.Select(s => s.Status).SingleAsync()));
            await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest()));
        }
        Assert.Equal(0, f.Provider.Exchanges); Assert.Equal(0, await f.Db(db => db.Connections.CountAsync()));
    }

    [Fact]
    public async Task LocalHandoffStillExpiresAfterTwoMinutes()
    {
        await using var f = new ServiceFixture { EnrolledReturnUri = LocalReturn, LocalBrowserReturns = [LocalReturn] };
        await f.Initialize(); var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie);
        f.Clock.Advance(TimeSpan.FromMinutes(2));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest)));
        Assert.False(await f.Db(db => db.Sessions.Select(s => s.Redeemed).SingleAsync()));
    }

    [Theory]
    [InlineData("authorization")]
    [InlineData("token")]
    [InlineData("revocation")]
    public async Task LocalBrowserAllowlistDoesNotAllowLocalProviderEndpoints(string endpoint)
    {
        await using var f = new ServiceFixture { LocalBrowserReturns = [LocalReturn] }; await f.Initialize();
        var config = new ConfigureProvider("local-provider", endpoint == "authorization" ? LocalReturn : "https://provider.example/authorize",
            endpoint == "token" ? LocalReturn : "https://provider.example/token", endpoint == "revocation" ? LocalReturn : "https://provider.example/revoke", "client", "synthetic-secret");
        using var response = await f.Http.PutAsJsonAsync("/operator/profiles", config);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(0, await f.Db(db => db.Profiles.CountAsync(p => p.Id == "local-provider")));
    }

    private sealed class NoOutboundClients : IHttpClientFactory
    {
        public int Calls;
        public HttpClient CreateClient(string name) { Calls++; throw new InvalidOperationException("Unexpected outbound HTTP client during browser return."); }
    }
}
