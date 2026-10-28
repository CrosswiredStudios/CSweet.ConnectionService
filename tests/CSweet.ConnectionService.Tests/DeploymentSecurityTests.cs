using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService.Tests;

public sealed class DeploymentSecurityTests
{
    [Theory]
    [InlineData("audience")]
    [InlineData("expiry")]
    [InlineData("future")]
    [InlineData("revision")]
    [InlineData("key-id")]
    [InlineData("path")]
    public async Task ProofRejectsMismatchedRequestBindings(string mutation)
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var now = f.Clock.GetUtcNow().ToUnixTimeSeconds();
        var proof = new DeploymentProof(f.Deployment.DeploymentId, "key-1", ServiceFixture.Origin, "GET", "/v1/events?after=0", DeploymentProofCodec.Hash(""), now, now + 30, DeploymentProofCodec.Random(), 1);
        proof = mutation switch
        {
            "audience" => proof with { Audience = "https://another.example" },
            "expiry" => proof with { ExpiresAt = now - 1 },
            "future" => proof with { IssuedAt = now + 20, ExpiresAt = now + 30 },
            "revision" => proof with { DeploymentRevision = 2 },
            "key-id" => proof with { KeyId = "copied-key-id" },
            _ => proof with { PathAndQuery = "/v1/events?after=1" }
        };
        using var request = f.Signed("/v1/events?after=0", overrideProof: proof); using var response = await f.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
    [Fact]
    public async Task ConsumedProofCannotBeReplayedEvenOnARead()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); using var request = f.Signed("/v1/events?after=0");
        var proof = request.Headers.GetValues(ConnectionProtocol.ProofHeader).Single(); using var first = await f.Http.SendAsync(request); first.EnsureSuccessStatusCode();
        using var replay = new HttpRequestMessage(HttpMethod.Get, "/v1/events?after=0"); replay.Headers.Add(ConnectionProtocol.ProofHeader, proof);
        using var response = await f.Http.SendAsync(replay); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
    [Fact]
    public async Task BodyTamperingAndWrongKeysAreRejectedBeforeAnyAttemptIsCreated()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); using var request = f.Signed("/v1/sessions", f.BeginRequest());
        request.Content = JsonContent.Create(f.BeginRequest() with { ActorId = "tampered" });
        using var response = await f.Http.SendAsync(request); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var forged = f.Signed("/v1/events?after=0", key: other);
        using var denied = await f.Http.SendAsync(forged); Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal(0, await f.Db(db => db.Sessions.CountAsync()));
    }
    [Fact]
    public async Task AnotherDeploymentCannotReadOrRedeemAConnection()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        var registration = await f.Http.PostAsJsonAsync("/operator/deployments", new EnrollDeployment("Another instance", DeploymentProofCodec.Encode(f.DeploymentKey.ExportSubjectPublicKeyInfo()), "key-1", [ServiceFixture.ReturnUri])); registration.EnsureSuccessStatusCode();
        var other = (await registration.Content.ReadFromJsonAsync<DeploymentRegistration>())!;
        var client = new ManagedConnectionClient(f.Http, new(ServiceFixture.Origin), other.DeploymentId, "key-1", 1, f.DeploymentKey, f.Clock);
        await Assert.ThrowsAsync<HttpRequestException>(() => client.Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest)));
        var result = await f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.Get(result.ConnectionId!.Value));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.Disconnect(result.ConnectionId!.Value));
        var events = await client.Events(0); Assert.DoesNotContain(events, x => x.ConnectionId == result.ConnectionId);
    }
    [Fact]
    public async Task CrossTenantAdministratorCannotRotateOrRevokeAnotherTenantsDeployment()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); f.Http.DefaultRequestHeaders.Authorization = new("Bearer", f.Token(tenant: "tenant-b"));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rotate = await f.Http.PostAsJsonAsync($"/operator/deployments/{f.Deployment.DeploymentId}/keys", new RotateDeploymentKey(DeploymentProofCodec.Encode(key.ExportSubjectPublicKeyInfo()), "other", 1));
        Assert.Equal(HttpStatusCode.Forbidden, rotate.StatusCode);
        using var revoke = await f.Http.PostAsync($"/operator/deployments/{f.Deployment.DeploymentId}/revoke", null); Assert.Equal(HttpStatusCode.Forbidden, revoke.StatusCode);
    }
    [Fact]
    public async Task KeyRotationAndRevocationInvalidateOldDeploymentProofsImmediately()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rotate = await f.Http.PostAsJsonAsync($"/operator/deployments/{f.Deployment.DeploymentId}/keys", new RotateDeploymentKey(DeploymentProofCodec.Encode(key.ExportSubjectPublicKeyInfo()), "key-2", 1)); rotate.EnsureSuccessStatusCode();
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Events(0));
        var next = new ManagedConnectionClient(f.Http, new(ServiceFixture.Origin), f.Deployment.DeploymentId, "key-2", 2, key, f.Clock);
        Assert.NotEmpty(await next.Events(0));
        using var revoke = await f.Http.PostAsync($"/operator/deployments/{f.Deployment.DeploymentId}/revoke", null); revoke.EnsureSuccessStatusCode();
        await Assert.ThrowsAsync<HttpRequestException>(() => next.Events(0));
        Assert.Contains(await f.Db(db => db.Events.ToArrayAsync()), x => x.Kind == "deployment.revoked" && x.OperatorSubject == "operator-1");
    }
    [Theory]
    [InlineData("anonymous")]
    [InlineData("wrong-role")]
    [InlineData("wrong-audience")]
    public async Task ProviderAdministrationRequiresTrustedOperatorIdentity(string identity)
    {
        await using var f = new ServiceFixture(); var http = f.NewClient();
        if (identity != "anonymous") http.DefaultRequestHeaders.Authorization = new("Bearer", identity == "wrong-role" ? f.Token("enterprise-administrator") : f.Token(audience: "other-service"));
        using var response = await http.PutAsJsonAsync("/operator/profiles", new ConfigureProvider("copied.profile", "copied-client", "https://provider.example/auth", "https://provider.example/token", "https://provider.example/revoke", "sensitive-secret"));
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
        Assert.DoesNotContain("sensitive-secret", await response.Content.ReadAsStringAsync());
    }
    [Fact]
    public async Task PackageAndProfileNamesDoNotGrantApproval()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest() with { PackageDigest = new string('f', 64) }));
        var forged = f.Manifest.Replace("https://oauth2.googleapis.com/token", "https://attacker.example/token", StringComparison.Ordinal);
        using var response = await f.Http.PostAsJsonAsync("/operator/packages", new ApprovePackage(DeploymentProofCodec.Hash("another-package"), DeploymentProofCodec.Hash(forged), forged, f.ProfileId, 1, "https://github.com/example/plugin", new string('b', 40)));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
    [Fact]
    public async Task RevokingPackageFencesConnectionsAndCannotBeSilentlyUndone()
    {
        await using var f = new ServiceFixture(); await f.Initialize(); var begin = f.BeginRequest(); var (_, state, cookie) = await f.Launch(begin); var h = await f.Callback(state, cookie);
        var receipt = await f.Client().Redeem(new(h, f.ReturnVerifier, begin.LocalAttemptId, begin.ActorId, f.Digest));
        using var revoke = await f.Http.PostAsync("/operator/packages/" + f.Digest + "/revoke", null); revoke.EnsureSuccessStatusCode();
        Assert.Equal("RevocationPending", (await f.Client().Get(receipt.ConnectionId!.Value)).Status);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().Begin(f.BeginRequest()));
        using var restore = await f.Http.PostAsJsonAsync("/operator/packages", new ApprovePackage(f.Digest, DeploymentProofCodec.Hash(f.Manifest), f.Manifest, f.ProfileId, 1, "https://github.com/example/connector", new string('a', 40)));
        Assert.Equal(HttpStatusCode.BadRequest, restore.StatusCode);
    }
    [Fact]
    public async Task ThereIsNoRawTokenOrMutationProxyEndpoint()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        foreach (var path in new[] { "/v1/tokens", "/v1/http", "/v1/execute" })
        { using var request = f.Signed(path, new { url = "https://unreviewed.example/mutate", approved = true }); using var response = await f.Http.SendAsync(request); Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); }
        Assert.Equal(0, f.Provider.Exchanges);
    }
}
