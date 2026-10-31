using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Tests;

public class OwnerControlTests
{
    private static readonly Guid Actor = Guid.Parse("8c988392-38dd-4e45-bb58-eb055dcba105");
    private static LocalOwnerCommand Bootstrap(ECDsa key, string tenant = "tenant-a", string[]? caps = null) => new("bootstrap", ServiceFixture.Origin,
        Guid.NewGuid(), DeploymentProofCodec.Encode(key.ExportSubjectPublicKeyInfo()), "owner-key", Actor, tenant,
        caps ?? [OwnerProtocol.Enroll, OwnerProtocol.Revoke], 0);
    private static async Task<T> Local<T>(ServiceFixture f, LocalOwnerCommand command)
    {
        await using var scope = f.Services.CreateAsyncScope();
        return (T)await scope.ServiceProvider.GetRequiredService<LocalOwnerAdministration>().Execute(command, default);
    }
    private static OwnerAdministrationClient Client(ServiceFixture f, OwnerRegistration r, ECDsa key) => new(f.Http, r, key, f.Clock);
    private static OwnerEnrollment Enrollment(string tenant = "tenant-a")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new(tenant, new("Customer", DeploymentProofCodec.Encode(key.ExportSubjectPublicKeyInfo()), "customer-key", [ServiceFixture.ReturnUri]));
    }
    [Fact]
    public async Task LocalOwnerWorksWithoutOidcAndCreatesOnlyExplicitTenantDeployment()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        Assert.Equal(HttpStatusCode.NotFound, (await f.Http.PostAsync("/operator/deployments", null)).StatusCode);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var command = Bootstrap(key);
        var registration = await Local<OwnerRegistration>(f, command); var client = Client(f, registration, key);
        var access = await client.Access(Actor); Assert.Equal("tenant-a", access.TenantScope);
        var deployment = await client.Enroll(Actor, access.GrantRevision, Enrollment());
        Assert.Equal("tenant-a", deployment.TenantId);
        await client.Revoke(Actor, access.GrantRevision, new("tenant-a", deployment.DeploymentId));
        Assert.True(await f.Db(db => db.Deployments.Where(x => x.Id == deployment.DeploymentId).Select(x => x.Revoked).SingleAsync()));
        var events = await f.Db(db => db.Events.Select(x => x.OperatorSubject).ToArrayAsync());
        Assert.Contains(events, x => x == $"owner:{registration.BindingId:D}/user:{Actor:D}");
    }
    [Theory]
    [InlineData("actor")]
    [InlineData("tenant")]
    [InlineData("revision")]
    [InlineData("key")]
    [InlineData("audience")]
    public async Task WrongAuthorityCannotEnroll(string change)
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var registration = await Local<OwnerRegistration>(f, Bootstrap(key));
        var client = Client(f, change == "audience" ? registration with { ServiceOrigin = "https://other.example.com" } : registration, change == "key" ? wrong : key);
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => client.Enroll(change == "actor" ? Guid.NewGuid() : Actor, change == "revision" ? 999 : 1, Enrollment(change == "tenant" ? "tenant-b" : "tenant-a")));
        Assert.Equal(0, await f.Db(db => db.Deployments.CountAsync()));
    }
    [Fact]
    public async Task CustomerKeyCannotBecomeOwnerOrCallControlPlane()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        var command = Bootstrap(f.DeploymentKey);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Local<object>(f, command));
        var customer = new OwnerRegistration(f.Deployment.DeploymentId, ServiceFixture.Origin, "key-1", 1);
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => Client(f, customer, f.DeploymentKey).Access(Actor));
    }
    [Fact]
    public async Task OwnerKeyCannotBecomeCustomerAndFailedMutationRollsBackNonceAndAudit()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var command = Bootstrap(key); var registration = await Local<OwnerRegistration>(f, command);
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => Client(f, registration, key).Enroll(Actor, 1, new("tenant-a", new("Bad", command.PublicKey!, "key", [ServiceFixture.ReturnUri]))));
        Assert.Equal(0, await f.Db(db => db.OwnerNonces.CountAsync()));
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync()));
    }
    [Fact]
    public void LocalCommandsRejectDuplicateUnknownAndOversizedInput()
    {
        Assert.Throws<ArgumentException>(() => LocalOwnerCommand.Parse(System.Text.Encoding.UTF8.GetBytes("{\"action\":\"grant\",\"action\":\"bootstrap\"}")));
        Assert.Throws<JsonException>(() => LocalOwnerCommand.Parse(System.Text.Encoding.UTF8.GetBytes("{\"unexpected\":true}")));
        Assert.Throws<ArgumentException>(() => LocalOwnerCommand.Parse(new byte[65537]));
    }

    [Fact]
    public async Task CustomerRotationCannotReuseAnOwnerKey()
    {
        await using var f = new ServiceFixture(); await f.Initialize();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var command = Bootstrap(key);
        await Local<OwnerRegistration>(f, command);
        await using var scope = f.Services.CreateAsyncScope();
        var registry = scope.ServiceProvider.GetRequiredService<RegistryService>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => registry.Rotate(f.Deployment.TenantId, "test", f.Deployment.DeploymentId,
            new(command.PublicKey!, "owner-reused", 1), default));
        Assert.Equal(1, await f.Db(db => db.Deployments.Where(x => x.Id == f.Deployment.DeploymentId).Select(x => x.Revision).SingleAsync()));
    }

    [Fact]
    public async Task GrantAndBindingRevocationAreImmediateAndRecoveryDoesNotRestoreOldKeys()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var command = Bootstrap(key); var registration = await Local<OwnerRegistration>(f, command); var client = Client(f, registration, key);
        await Local<object>(f, command with { Action = "revoke-grant", ExpectedRevision = 1 });
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => client.Access(Actor));
        await Local<object>(f, command with { Action = "grant", ExpectedRevision = 2 });
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => client.Enroll(Actor, 1, Enrollment()));
        Assert.Equal(3, (await client.Access(Actor)).GrantRevision);
        await Local<object>(f, command with { Action = "revoke-binding", ExpectedRevision = 1 });
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => client.Access(Actor));
        using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256); var recovered = await Local<OwnerRegistration>(f, Bootstrap(replacement));
        Assert.NotEqual(registration.BindingId, (await Client(f, recovered, replacement).Access(Actor)).Registration.BindingId);
    }
    [Fact]
    public async Task ReplayAndBodyTamperingFailAndAuditIsContentFree()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var registration = await Local<OwnerRegistration>(f, Bootstrap(key));
        var body = JsonSerializer.SerializeToUtf8Bytes(new OwnerRequest<OwnerEnrollment>(Actor, 1, Enrollment()), DeploymentProofCodec.Json);
        var now = f.Clock.GetUtcNow().ToUnixTimeSeconds(); var proof = new DeploymentProof(registration.BindingId, "owner-key", ServiceFixture.Origin + OwnerProtocol.AudienceSuffix, "POST", "/owner-control/v1/deployments/enroll", DeploymentProofCodec.Hash(body), now, now + 30, DeploymentProofCodec.Random(), 1);
        HttpRequestMessage Request(byte[] bytes) { var r = new HttpRequestMessage(HttpMethod.Post, proof.PathAndQuery) { Content = new ByteArrayContent(bytes) }; r.Headers.Add(OwnerProtocol.ProofHeader, DeploymentProofCodec.Sign(proof, key)); return r; }
        using (var altered = Request("{}"u8.ToArray())) Assert.Equal(HttpStatusCode.Forbidden, (await f.Http.SendAsync(altered)).StatusCode);
        using (var first = Request(body)) Assert.Equal(HttpStatusCode.OK, (await f.Http.SendAsync(first)).StatusCode);
        using (var replay = Request(body)) Assert.Equal(HttpStatusCode.Conflict, (await f.Http.SendAsync(replay)).StatusCode);
        Assert.Equal(1, await f.Db(db => db.Deployments.CountAsync()));
    }
    [Fact]
    public async Task TenantScopedGrantCannotImportCredentialsOrApprovePackages()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var registration = await Local<OwnerRegistration>(f, Bootstrap(key));
        using var json = JsonDocument.Parse("{}");
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => Client(f, registration, key).Import(Actor, 1, new("google-web-client", "provider", json.RootElement)));
        Assert.Equal(0, await f.Db(db => db.Profiles.CountAsync()));
    }
}
