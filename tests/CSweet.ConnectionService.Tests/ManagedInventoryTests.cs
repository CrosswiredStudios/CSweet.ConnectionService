using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using CSweet.ConnectionService.OAuth.Google;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedInventoryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReviewedInventoryUsesOnlyDeclaredMappingsAndReturnsNoCredentials(bool alternate)
    {
        await using var f = new InventoryFixture(); await f.Initialize(alternate);
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var handoff = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(handoff, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        var inventory = await f.Client().Discover(receipt.ConnectionId!.Value);
        Assert.Equal("Ready", inventory.Status); Assert.Equal("provider-subject", inventory.Subject); Assert.Single(inventory.Resources);
        Assert.Equal(2, f.Api.Calls); Assert.DoesNotContain("secret-", JsonSerializer.Serialize(inventory));
        Assert.Equal(inventory.Resources, (await f.Client().Discover(receipt.ConnectionId.Value)).Resources); Assert.Equal(2, f.Api.Calls);
        Assert.DoesNotContain("Provider account", (await f.Db(db => db.Connections.SingleAsync())).ProtectedInventory);
    }

    [Fact]
    public async Task DiscoveryCannotCrossDeploymentsOrRunAfterDisconnect()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(Guid.NewGuid())); Assert.Equal(0, f.Api.Calls);
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        await f.Client().Disconnect(receipt.ConnectionId!.Value);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(receipt.ConnectionId.Value)); Assert.Equal(0, f.Api.Calls);
    }

    [Fact]
    public async Task ProviderRevocationIsConfirmedBeforePrimaryCredentialsAreErased()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        await f.Client().Disconnect(receipt.ConnectionId!.Value);
        await using var scope = f.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ConnectionRevocationService>().Process(default);
        var stored = await f.Db(db => db.Connections.SingleAsync());
        Assert.Equal("Revoked", stored.Status); Assert.Empty(stored.ProtectedCredentials); Assert.Empty(stored.ProtectedInventory); Assert.Equal(1, f.Provider.Revocations);
    }

    [Fact]
    public async Task RefreshNeverReturnsTokensToTheDeployment()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        f.Clock.Advance(TimeSpan.FromHours(2));
        var inventory = await f.Client().Discover(receipt.ConnectionId!.Value);
        Assert.Equal("Ready", inventory.Status); Assert.Equal(1, f.Provider.Refreshes); Assert.DoesNotContain("refreshed-access", JsonSerializer.Serialize(inventory));
    }

    [Fact]
    public async Task UncertainRefreshIsFencedAndNeverReplaysTheOldRefreshToken()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        f.Clock.Advance(TimeSpan.FromHours(2)); f.Provider.FailRefresh = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(receipt.ConnectionId!.Value));
        f.Provider.FailRefresh = false;
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(receipt.ConnectionId!.Value));
        Assert.Equal(1, f.Provider.Refreshes); Assert.Equal(0, f.Api.Calls);
        Assert.Equal("ConnectionRequired", (await f.Client().Get(receipt.ConnectionId!.Value)).Status);
    }
    [Fact]
    public async Task RefreshCannotPromoteAdditionalProviderScopesIntoReviewedAuthority()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        using var declaration = JsonDocument.Parse(f.Manifest);
        f.Provider.RefreshScopes = declaration.RootElement.GetProperty("connections")[0].GetProperty("scopeSets").EnumerateArray()
            .Where(x => x.GetProperty("id").GetString() == "base").SelectMany(x => x.GetProperty("scopes").EnumerateArray()).Select(x => x.GetString()!)
            .Append("unreviewed-permission").ToArray();
        f.Clock.Advance(TimeSpan.FromHours(2));
        var inventory = await f.Client().Discover(receipt.ConnectionId!.Value);
        Assert.Equal("Ready", inventory.Status); Assert.Equal(["base"], inventory.GrantedScopeSets);
        Assert.Equal(["base"], (await f.Client().Get(receipt.ConnectionId!.Value)).GrantedScopeSets);
    }
    [Fact]
    public async Task VerifiedReplacementRetiresOnlyTheOldServiceGrantWithoutRevokingTheNewProviderConsent()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        async Task<Guid> Connect(BeginConnection request)
        {
            var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
            var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
            await f.Client().Discover(receipt.ConnectionId!.Value); return receipt.ConnectionId.Value;
        }
        var original = f.BeginRequest(); var oldConnection = await Connect(original);
        var wrongInstallation = await Connect(f.BeginRequest());
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Supersede(oldConnection, wrongInstallation));
        var replacement = await Connect(original with { LocalAttemptId = Guid.NewGuid() });
        var retired = await f.Client().Supersede(oldConnection, replacement);
        Assert.Equal("Superseded", retired.Status); Assert.Equal("Ready", (await f.Client().Get(replacement)).Status);
        Assert.Equal(0, f.Provider.Revocations);
        Assert.Empty((await f.Db(db => db.Connections.SingleAsync(x => x.Id == oldConnection))).ProtectedCredentials);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(oldConnection));
    }
    [Fact]
    public async Task GoogleCanonicalScopeAliasesWorkWithoutChangingOtherProvidersOrEnablingExtraSets()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        using var manifest = JsonDocument.Parse(f.Manifest);
        var scopes = manifest.RootElement.GetProperty("connections")[0].GetProperty("scopeSets").EnumerateArray()
            .Single(x => x.GetProperty("id").GetString() == "base").GetProperty("scopes").EnumerateArray().Select(x => x.GetString()!).ToArray();
        f.Provider.GrantedScopes = scopes.Select(x => x == "profile" ? "https://www.googleapis.com/auth/userinfo.profile" : x).ToArray();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        Assert.Equal("Ready", (await f.Client().Discover(receipt.ConnectionId!.Value)).Status);
        var convention = new OAuthScopeConventions([new GoogleOAuthScopeConvention()]);
        var profile = await f.Db(db => db.Profiles.SingleAsync());
        Assert.StartsWith("openid ", convention.AuthorizationValue(profile, scopes));
        Assert.Contains("https://www.googleapis.com/auth/userinfo.profile", convention.Canonical(profile, ["profile"]));
        profile.TokenEndpoint = "https://another.example/token";
        Assert.Contains("profile", convention.Canonical(profile, ["profile"]));
    }
    [Fact]
    public async Task MissingRequiredPermissionsOnRefreshFenceTheConnection()
    {
        await using var f = new InventoryFixture(); await f.Initialize();
        var request = f.BeginRequest(); var (_, state, cookie) = await f.Launch(request); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, request.LocalAttemptId, request.ActorId, f.Digest));
        f.Provider.RefreshScopes = ["openid"]; f.Clock.Advance(TimeSpan.FromHours(2));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Discover(receipt.ConnectionId!.Value));
        Assert.Equal("ConnectionRequired", (await f.Client().Get(receipt.ConnectionId!.Value)).Status); Assert.Equal(0, f.Api.Calls);
    }
    [Fact]
    public async Task GoogleImportValidatesExactCallbackAndNormalizesTheLegacyExportEndpoint()
    {
        var reader = new GoogleOAuthCredentialDocumentReader();
        var json = JsonSerializer.SerializeToElement(new
        {
            web = new
            {
                client_id = "client",
                client_secret = "sensitive-secret",
                project_id = "project-one",
                auth_uri = "https://accounts.google.com/o/oauth2/auth",
                token_uri = "https://oauth2.googleapis.com/token",
                redirect_uris = new[] { "https://connections.example.com/oauth/callback/profile-one" }
            }
        });
        var profile = reader.Read("profile-one", json, "https://connections.example.com/oauth/callback/profile-one");
        Assert.Equal("https://accounts.google.com/o/oauth2/v2/auth", profile.AuthorizationEndpoint); Assert.Equal("project-one", profile.RevocationGroup);
        Assert.DoesNotContain("sensitive-secret", profile.ToString());
        Assert.Throws<ArgumentException>(() => reader.Read("profile-two", json, "https://connections.example.com/oauth/callback/profile-two"));
    }
    private sealed class InventoryFixture : ServiceFixture
    {
        public readonly ApiProvider Api = new();
        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
        { base.ConfigureWebHost(builder); builder.ConfigureServices(services => { services.RemoveAll<IProviderApiTransport>(); services.AddSingleton<IProviderApiTransport>(Api); }); }
    }
    private sealed class ApiProvider : IProviderApiTransport
    {
        public int Calls;
        public Task<JsonElement> Read(Uri destination, string accessToken, CancellationToken ct)
        {
            Assert.Contains(accessToken, new[] { "secret-access-token", "refreshed-access" }); Calls++;
            return Task.FromResult(destination.AbsolutePath.Contains("userinfo", StringComparison.Ordinal)
                ? JsonSerializer.SerializeToElement(new { sub = "provider-subject", name = "Provider account" })
                : JsonSerializer.SerializeToElement(new { items = new[] { new { id = "channel-one", snippet = new { title = "My channel", customUrl = "@my-channel" } } } }));
        }
    }
}
