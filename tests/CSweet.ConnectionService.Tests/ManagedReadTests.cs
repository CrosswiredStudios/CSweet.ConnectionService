using System.Net;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedReadTests
{
    [Fact]
    public async Task EnrollmentDoesNotAuthorizeExecutionAndAnExactPolicyIsRequired()
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready();
        await Rejected(f, id, request); Assert.Equal(0, f.Api.ExecutionCalls);
        f.Allow(); Assert.Equal(id, (await f.Client().ReadOperation(id, request)).ConnectionId);
        Assert.Equal(1, f.Api.ExecutionCalls);
        Assert.Equal("channel-one", f.Api.LastQuery!["id"]);
        Assert.False(f.Api.LastQuery.ContainsKey("mine"));
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync(x => x.Kind == "connection.operation-read")));
        Assert.DoesNotContain("secret-access-token", JsonSerializer.Serialize(await f.Client().ReadOperation(id, request)));
        Assert.DoesNotContain(f.Logs.Messages, x => x.Contains("secret-access-token", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("tenant")]
    [InlineData("installation")]
    [InlineData("requester")]
    [InlineData("package")]
    [InlineData("resource")]
    [InlineData("capability")]
    [InlineData("bootstrap")]
    [InlineData("write")]
    [InlineData("scope")]
    [InlineData("input")]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("policy-tenant")]
    [InlineData("policy-package")]
    public async Task WrongAuthorityOrUnsupportedMappingsNeverReachTheProvider(string change)
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow();
        request = change switch
        {
            "tenant" => request with { TenantId = "tenant-other" },
            "installation" => request with { InstallationId = Guid.NewGuid() },
            "requester" => request with { RequesterInstallationId = Guid.Empty },
            "package" => request with { PackageDigest = new string('b', 64) },
            "resource" => request with { ResourceId = "channel-other" },
            "capability" => request with { Capability = "unknown.operation.v1" },
            "bootstrap" => request with { Capability = "youtube.api.channel.discover.v1" },
            "write" => request with { Capability = "youtube.api.comment.reply.v1" },
            "scope" => request with { Capability = "youtube.api.member.list.v1" },
            "input" => request with { Input = JsonSerializer.SerializeToElement(new { unexpected = "value" }) },
            "expired" => request with { ExpiresAt = f.Clock.GetUtcNow().ToUnixTimeSeconds() },
            "future" => request with { ExpiresAt = f.Clock.GetUtcNow().ToUnixTimeSeconds() + 61 },
            _ => request
        };
        var policy = f.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies.Single();
        if (change == "policy-tenant") policy.TenantId = "tenant-other";
        if (change == "policy-package") policy.PackageDigests = [new string('b', 64)];
        await Rejected(f, id, request); Assert.Equal(0, f.Api.ExecutionCalls);
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "connection.operation-read")));
    }

    [Theory]
    [InlineData("disconnect")]
    [InlineData("deployment")]
    [InlineData("package")]
    [InlineData("profile")]
    [InlineData("policy")]
    [InlineData("inventory-expired")]
    public async Task ChangedAuthorityDuringProviderReadWithholdsResultAndAudit(string change)
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow();
        f.Api.AfterRead = async () =>
        {
            if (change == "disconnect") await f.Client().Disconnect(id);
            else if (change == "policy") f.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies = [];
            else if (change == "inventory-expired") f.Clock.Advance(TimeSpan.FromDays(10));
            else if (change == "deployment") await f.Db(async db => { (await db.Deployments.SingleAsync()).Revision++; return await db.SaveChangesAsync(); });
            else
            {
                await using var scope = f.Services.CreateAsyncScope(); var registry = scope.ServiceProvider.GetRequiredService<RegistryService>();
                if (change == "package") await registry.RevokePackage("operator", f.Digest, default);
                else await registry.DisableProfile("operator", f.ProfileId, default);
            }
        };
        await Rejected(f, id, request); Assert.Equal(1, f.Api.ExecutionCalls);
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "connection.operation-read")));
    }

    [Fact]
    public async Task ResourceOwnershipCheckIsMaterializedFromReviewedDeclaration()
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow();
        request = request with { Capability = "youtube.api.video.read.v1", Input = JsonSerializer.SerializeToElement(new { videoId = "video-one01" }) };
        f.Api.WrongOwner = true; await Rejected(f, id, request); Assert.Equal(1, f.Api.ExecutionCalls);
        Assert.Equal("video-one01", f.Api.LastQuery!["id"]);
        f.Api.WrongOwner = false; Assert.Equal(id, (await f.Client().ReadOperation(id, request)).ConnectionId);
        Assert.Equal(3, f.Api.ExecutionCalls);
    }

    [Fact]
    public async Task ReviewedResponseResourcePointersRejectAnotherChannel()
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(["base", "memberships"]); f.Allow();
        request = request with { Capability = "youtube.api.membership-level.list.v1" };
        f.Api.ResultOverride = JsonSerializer.SerializeToElement(new { items = new[] { new { id = "level", snippet = new
            { creatorChannelId = "channel-other", levelDetails = new { displayName = "Level" } } } } });
        await Rejected(f, id, request); Assert.Equal(1, f.Api.ExecutionCalls);
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "connection.operation-read")));
        f.Api.ResultOverride = JsonSerializer.SerializeToElement(new { items = new[] { new { id = "level", snippet = new
            { creatorChannelId = "channel-one", levelDetails = new { displayName = "Level" } } } } });
        Assert.Equal(id, (await f.Client().ReadOperation(id, request)).ConnectionId);
    }

    [Theory]
    [InlineData("oversize")]
    [InlineData("duplicate")]
    public async Task AmbiguousOrOversizedProviderResultsAreWithheld(string shape)
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow();
        f.Api.ResultOverride = shape == "oversize" ? JsonSerializer.SerializeToElement(new { content = new string('x', ManagedExecutionProtocol.MaximumReadResultBytes) })
            : JsonDocument.Parse("{\"items\":[],\"items\":[]}").RootElement.Clone();
        await Rejected(f, id, request); Assert.Equal(1, f.Api.ExecutionCalls);
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "connection.operation-read")));
    }

    [Fact]
    public async Task SignedRequestReplayIsRejectedBeforeAnotherProviderRead()
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow();
        var path = $"/v1/connections/{id:D}/operations/read"; using var first = f.Signed(path, request);
        var proof = first.Headers.GetValues(ConnectionProtocol.ProofHeader).Single();
        using var accepted = await f.Http.SendAsync(first); Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using var replay = f.Signed(path, request); replay.Headers.Remove(ConnectionProtocol.ProofHeader); replay.Headers.Add(ConnectionProtocol.ProofHeader, proof);
        using var rejected = await f.Http.SendAsync(replay); Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        Assert.Equal(1, f.Api.ExecutionCalls);
    }

    [Fact]
    public async Task ProviderFailureContentIsNeverReturnedOrLogged()
    {
        await using var f = new ReadFixture(); var (id, request) = await f.Ready(); f.Allow(); f.Api.Fail = true;
        using var response = await f.Http.SendAsync(f.Signed($"/v1/connections/{id:D}/operations/read", request));
        Assert.False(response.IsSuccessStatusCode);
        Assert.DoesNotContain("synthetic-provider-secret", await response.Content.ReadAsStringAsync());
        Assert.DoesNotContain(f.Logs.Messages, x => x.Contains("synthetic-provider-secret", StringComparison.Ordinal));
        Assert.Equal(1, f.Api.ExecutionCalls);
    }

    private static async Task Rejected(ReadFixture f, Guid id, ManagedReadRequest request)
    { await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().ReadOperation(id, request)); }

    private sealed class ReadFixture : ServiceFixture
    {
        public readonly ReadProvider Api = new();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder); builder.ConfigureServices(services =>
            { services.RemoveAll<IProviderApiTransport>(); services.AddSingleton<IProviderApiTransport>(Api); });
        }
        public void Allow() => Services.GetRequiredService<ServiceOptions>().ExecutionPolicies =
            [new() { DeploymentId = Deployment.DeploymentId, TenantId = Deployment.TenantId, PackageDigests = [Digest], AllowReads = true }];
        public async Task<(Guid, ManagedReadRequest)> Ready(string[]? scopeSets = null)
        {
            await Initialize(); var begin = BeginRequest(scopeSets); var (_, state, cookie) = await Launch(begin);
            var handoff = await Callback(state, cookie);
            var receipt = await Client().Redeem(new(handoff, ReturnVerifier, begin.LocalAttemptId, begin.ActorId, Digest));
            var id = receipt.ConnectionId!.Value; Assert.Equal("Ready", (await Client().Discover(id)).Status); Api.Ready = true;
            return (id, new(Deployment.TenantId, begin.InstallationId, Guid.NewGuid(), Digest, "youtube.api.channel.read.v1", "channel-one",
                JsonSerializer.SerializeToElement(new { }), new string('a', 64), Clock.GetUtcNow().ToUnixTimeSeconds() + 30));
        }
    }
    private sealed class ReadProvider : IProviderApiTransport
    {
        public bool Ready, WrongOwner, Fail; public int ExecutionCalls; public Func<Task>? AfterRead;
        public JsonElement? ResultOverride;
        public Dictionary<string, string>? LastQuery;
        public async Task<JsonElement> Read(Uri destination, string accessToken, CancellationToken ct)
        {
            Assert.Equal("secret-access-token", accessToken);
            Assert.Contains(destination.Host, new[] { "openidconnect.googleapis.com", "www.googleapis.com" });
            if (Ready)
            {
                ExecutionCalls++; LastQuery = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(destination.Query).ToDictionary(x => x.Key, x => x.Value.ToString());
                if (Fail) throw new HttpRequestException("synthetic-provider-secret", null, HttpStatusCode.BadGateway);
                if (AfterRead is not null) await AfterRead();
                if (ResultOverride is { } result) return result;
            }
            if (destination.AbsolutePath.Contains("userinfo", StringComparison.Ordinal))
                return JsonSerializer.SerializeToElement(new { sub = "provider-subject", name = "Provider account" });
            if (Ready && destination.AbsolutePath.EndsWith("/videos", StringComparison.Ordinal))
                return JsonSerializer.SerializeToElement(new { items = new[] { new { id = "video-one01", snippet = new { channelId = WrongOwner ? "channel-other" : "channel-one", title = "Video" } } } });
            return JsonSerializer.SerializeToElement(new { items = new[] { new { id = "channel-one", snippet = new { title = "My channel", customUrl = "@channel" } } } });
        }
    }
}
