using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedMediaTests
{
    [Theory]
    [InlineData("begin", "disconnect")]
    [InlineData("begin", "deployment")]
    [InlineData("begin", "package")]
    [InlineData("begin", "profile")]
    [InlineData("begin", "policy")]
    [InlineData("begin", "cancel")]
    [InlineData("begin", "lease")]
    [InlineData("begin", "expired")]
    [InlineData("probe", "disconnect")]
    [InlineData("probe", "deployment")]
    [InlineData("probe", "package")]
    [InlineData("probe", "profile")]
    [InlineData("probe", "policy")]
    [InlineData("probe", "cancel")]
    [InlineData("probe", "lease")]
    [InlineData("probe", "expired")]
    public async Task CachedMediaReceiptsCannotReleaseResultsAfterAuthorityOrCancellationChanges(string path, string change)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var start = await f.Client().BeginMedia(id, request);
        Assert.Equal("Completed", (await f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17])).State);
        f.Cached.Arm(1, () =>
        {
            async Task Change()
            {
                if (change == "disconnect") await f.Client().Disconnect(id);
                else if (change == "cancel") await f.Client().CancelMedia(start.TransferId, start.BindingHash);
                else if (change == "deployment") await f.Db(async db => { (await db.Deployments.SingleAsync()).Revision++; return await db.SaveChangesAsync(); });
                else if (change == "policy") f.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies = [];
                else if (change is "lease" or "expired") await f.Db(async db =>
                {
                    var row = await db.MediaTransfers.SingleAsync();
                    if (change == "lease") { row.LeaseOwner = Guid.NewGuid(); row.LeaseUntil = f.Clock.GetUtcNow().ToUnixTimeSeconds() + 20; }
                    else row.ValidUntil = f.Clock.GetUtcNow().ToUnixTimeSeconds() - 1;
                    row.Revision++; return await db.SaveChangesAsync();
                });
                else
                {
                    await using var scope = f.Services.CreateAsyncScope(); var registry = scope.ServiceProvider.GetRequiredService<RegistryService>();
                    if (change == "package") await registry.RevokePackage("operator", f.Digest, default);
                    else await registry.DisableProfile("operator", f.ProfileId, default);
                }
            }
            Change().GetAwaiter().GetResult();
        });
        var result = path == "begin" ? f.Client().BeginMedia(id, request) : f.Client().ProbeMedia(start.TransferId, start.BindingHash);
        await Assert.ThrowsAsync<HttpRequestException>(() => result);
        Assert.True(f.Cached.Injected); Assert.Equal(1, f.Media.Begins); Assert.Equal(1, f.Media.Exchanges);
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync(x => x.Kind == "media.completed")));
    }

    [Theory]
    [InlineData("begin")]
    [InlineData("probe")]
    public async Task CachedReceiptValidationAndMaterializationShareTheAuthorityWriteFence(string path)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var start = await f.Client().BeginMedia(id, request);
        await f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17]);
        var blocked = false;
        f.Cached.Arm(2, () =>
        {
            using var writer = new SqliteConnection("Data Source=" + Path.Combine(f.Root, "connections.db") + ";Default Timeout=1");
            writer.Open(); using var command = writer.CreateCommand(); command.CommandText = "UPDATE Deployments SET Revision = Revision + 1";
            try { command.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 5) { blocked = true; }
        });
        var result = path == "begin" ? await f.Client().BeginMedia(id, request) : await f.Client().ProbeMedia(start.TransferId, start.BindingHash);
        Assert.Equal("Completed", result.State); Assert.True(f.Cached.Injected); Assert.True(blocked);
        Assert.Equal(1, f.Media.Begins); Assert.Equal(1, f.Media.Exchanges);
    }
    [Theory]
    [InlineData("destination")]
    [InlineData("headers")]
    public async Task UnknownProxyFieldsAreRejectedBeforeAnyProviderOperation(string field)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var body = JsonSerializer.SerializeToNode(request, DeploymentProofCodec.Json)!;
        body[field] = "https://untrusted.example/never-send";
        using var response = await f.Http.SendAsync(f.Signed($"/v1/connections/{id:D}/media", body));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(0, f.Media.Begins);
        Assert.False(await f.Db(db => db.MediaTransfers.AnyAsync()));
    }
    [Fact]
    public async Task ANewServiceInstanceRecoversOnlyTheSavedSessionAndOffset()
    {
        await using var original = new MediaFixture(); var (id, request) = await original.Ready(256 * 1024 + 17); original.Allow();
        var start = await original.Client().BeginMedia(id, request);
        await original.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[256 * 1024]);
        await using var restarted = new MediaFixture(existingRoot: original.Root, existingProvider: original.Media);
        restarted.Http = restarted.NewClient();
        restarted.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies = original.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies;
        var client = new ManagedConnectionClient(restarted.Http, new(ServiceFixture.Origin), original.Deployment.DeploymentId, "key-1", original.Deployment.Revision, original.DeploymentKey, original.Clock);
        Assert.Equal(256 * 1024, (await client.ProbeMedia(start.TransferId, start.BindingHash)).CommittedBytes);
        Assert.Equal("Completed", (await client.MediaChunk(start.TransferId, start.BindingHash, 256 * 1024, new byte[17])).State);
        Assert.Equal(1, original.Media.Begins);
    }

    [Fact]
    public async Task FailedCompletionCommitRetainsProbeRecoveryAndRollsBackTheCompletionAudit()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        f.Saves.FailCompletion = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17]));
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "media.completed")));
        var pending = await f.Db(db => db.MediaTransfers.SingleAsync()); Assert.Equal("ProbeRequired", pending.State); Assert.NotEmpty(pending.ProtectedSession);
        Assert.Empty(pending.ProtectedResult); f.Saves.FailCompletion = false;
        Assert.Equal("Completed", (await f.Client().ProbeMedia(start.TransferId, start.BindingHash)).State);
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync(x => x.Kind == "media.completed")));
        Assert.Equal(1, f.Media.Begins);
    }

    [Fact]
    public async Task FinalMediaValidationAndSaveHoldTheAuthorityWriteFence()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        var blocked = false;
        f.Saves.BeforeCompletion = () =>
        {
            using var writer = new SqliteConnection("Data Source=" + Path.Combine(f.Root, "connections.db") + ";Default Timeout=1");
            writer.Open(); using var command = writer.CreateCommand(); command.CommandText = "UPDATE Deployments SET Revision = Revision + 1";
            try { command.ExecuteNonQuery(); } catch (SqliteException e) when (e.SqliteErrorCode == 5) { blocked = true; }
        };
        Assert.Equal("Completed", (await f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17])).State);
        Assert.True(blocked);
    }
    [Theory]
    [InlineData("allOf")]
    [InlineData("not")]
    public async Task UnsupportedOutputSchemasCannotInitiateMedia(string keyword)
    {
        await using var f = new MediaFixture(unsupportedOutput: keyword); var (id, request) = await f.Ready(); f.Allow();
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request));
        Assert.Equal(0, f.Media.Begins); Assert.False(await f.Db(db => db.MediaTransfers.AnyAsync()));
    }
    [Fact]
    public async Task ConcurrentInitiationSharesOneDurableClaim()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Media.BeforeBegin = async () => { entered.SetResult(); await release.Task; };
        var first = f.Client().BeginMedia(id, request); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try { await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request)); }
        finally { release.TrySetResult(); }
        Assert.Equal("Ready", (await first).State); Assert.Equal(1, f.Media.Begins);
        Assert.Equal(1, await f.Db(db => db.MediaTransfers.CountAsync()));
    }

    [Fact]
    public async Task ChunkProofBindsExactBytesAndReplayCannotResendAProviderMutation()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        var path = $"/v1/media/{start.TransferId:D}/chunks/0/{start.BindingHash}"; var bytes = new byte[17];
        var now = f.Clock.GetUtcNow().ToUnixTimeSeconds();
        var proof = new DeploymentProof(f.Deployment.DeploymentId, "key-1", ServiceFixture.Origin, "POST", path, DeploymentProofCodec.Hash(bytes), now, now + 30, DeploymentProofCodec.Random(), f.Deployment.Revision);
        HttpRequestMessage Message(byte[] body) { var message = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ByteArrayContent(body) };
            message.Content.Headers.ContentType = new("application/octet-stream"); message.Headers.Add(ConnectionProtocol.ProofHeader, DeploymentProofCodec.Sign(proof, f.DeploymentKey)); return message; }
        var tampered = bytes.ToArray(); tampered[0] = 1;
        using (var response = await f.Http.SendAsync(Message(tampered))) Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, f.Media.Exchanges);
        using (var response = await f.Http.SendAsync(Message(bytes))) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using (var response = await f.Http.SendAsync(Message(bytes))) Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, f.Media.Exchanges);
    }

    [Fact]
    public async Task AnotherDeploymentCannotBorrowAnOpaqueTransferOrItsPlanHash()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var response = await f.Http.PostAsJsonAsync("/operator/deployments", new EnrollDeployment("Other synthetic deployment", DeploymentProofCodec.Encode(otherKey.ExportSubjectPublicKeyInfo()), "other-key", [ServiceFixture.ReturnUri]));
        response.EnsureSuccessStatusCode(); var registration = (await response.Content.ReadFromJsonAsync<DeploymentRegistration>())!;
        var other = new ManagedConnectionClient(f.Http, new(ServiceFixture.Origin), registration.DeploymentId, "other-key", registration.Revision, otherKey, f.Clock);
        await Assert.ThrowsAsync<HttpRequestException>(() => other.ProbeMedia(start.TransferId, start.BindingHash));
        await Assert.ThrowsAsync<HttpRequestException>(() => other.CancelMedia(start.TransferId, start.BindingHash));
        Assert.Equal(0, f.Media.Exchanges); Assert.Equal("Ready", (await f.Db(db => db.MediaTransfers.SingleAsync())).State);
    }

    [Fact]
    public async Task LargeBinaryBodiesDoNotRelaxExistingJsonRoutes()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var path = $"/v1/connections/{id:D}/inventory"; var bytes = new byte[2 * 1024 * 1024]; var now = f.Clock.GetUtcNow().ToUnixTimeSeconds();
        using var message = new HttpRequestMessage(HttpMethod.Post, path) { Content = new ByteArrayContent(bytes) };
        message.Content.Headers.ContentType = new("application/octet-stream"); message.Headers.Add(ConnectionProtocol.ProofHeader, DeploymentProofCodec.Sign(new(f.Deployment.DeploymentId,
            "key-1", ServiceFixture.Origin, "POST", path, DeploymentProofCodec.Hash(bytes), now, now + 30, DeploymentProofCodec.Random(), f.Deployment.Revision), f.DeploymentKey));
        using var response = await f.Http.SendAsync(message); Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(0, f.Media.Begins);
    }
    [Fact]
    public async Task DurableMediaNeverExportsSessionOrCredentialsAndRepeatedInitiationIsIdempotent()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(ManagedExecutionProtocol.MaximumChunkBytes + 17); f.Allow();
        var started = await f.Client().BeginMedia(id, request);
        Assert.Equal("Ready", started.State); Assert.Equal(1, f.Media.Begins);
        var repeat = await f.Client().BeginMedia(id, request with { Operation = request.Operation with { ExpiresAt = request.Operation.ExpiresAt + 1 } });
        Assert.Equal(started.TransferId, repeat.TransferId); Assert.Equal(1, f.Media.Begins);
        var stored = await f.Db(db => db.MediaTransfers.SingleAsync());
        Assert.DoesNotContain("private-session", stored.ProtectedSession); Assert.NotEmpty(stored.ProtectedSession);
        Assert.DoesNotContain("Synthetic private title", stored.ProtectedRequest);
        Assert.DoesNotContain("private-session", JsonSerializer.Serialize(started));
        var probe = await f.Client().ProbeMedia(started.TransferId, started.BindingHash); Assert.Equal(0, probe.CommittedBytes);
        var chunk = await f.Client().MediaChunk(started.TransferId, started.BindingHash, 0, new byte[ManagedExecutionProtocol.MaximumChunkBytes]);
        Assert.Equal(308, chunk.StatusCode); Assert.Equal(ManagedExecutionProtocol.MaximumChunkBytes, chunk.CommittedBytes);
        var completed = await f.Client().MediaChunk(started.TransferId, started.BindingHash, chunk.CommittedBytes, new byte[17]);
        Assert.Equal("Completed", completed.State); Assert.Equal(request.SizeBytes, completed.CommittedBytes);
        Assert.Equal("video-one01", completed.Result!.Value.GetProperty("id").GetString());
        var again = await f.Client().ProbeMedia(started.TransferId, started.BindingHash);
        Assert.Equal("Completed", again.State); Assert.Equal(3, f.Media.Exchanges);
        Assert.Empty((await f.Db(db => db.MediaTransfers.SingleAsync())).ProtectedSession);
        Assert.DoesNotContain(f.Logs.Messages, x => x.Contains("private-session", StringComparison.Ordinal) || x.Contains("secret-access-token", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("default-deny")]
    [InlineData("missing-scope")]
    [InlineData("resource")]
    [InlineData("tenant")]
    [InlineData("asset")]
    [InlineData("expiry")]
    [InlineData("content-type")]
    [InlineData("multiple-resources")]
    [InlineData("missing-result-binding")]
    public async Task MediaAuthorityFailsClosedBeforeInitiation(string failure)
    {
        await using var f = new MediaFixture(failure != "missing-result-binding");
        if (failure == "multiple-resources") f.Media.MultipleResources = true;
        var (id, request) = await f.Ready(17, failure == "missing-scope" ? ["base"] : null);
        if (failure != "default-deny") f.Allow();
        request = failure switch
        {
            "resource" => request with { Operation = request.Operation with { ResourceId = "channel-other" } },
            "tenant" => request with { Operation = request.Operation with { TenantId = "tenant-other" } },
            "asset" => request with { AssetId = Guid.NewGuid() },
            "expiry" => request with { ValidUntil = f.Clock.GetUtcNow().ToUnixTimeSeconds() },
            "content-type" => request with { ContentType = "video/mp4; unexpected=parameter" },
            _ => request
        };
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request)); Assert.Equal(0, f.Media.Begins);
        Assert.False(await f.Db(db => db.MediaTransfers.AnyAsync()));
    }

    [Fact]
    public async Task LostInitiationNeverStartsAReplacementAndChangedContentCannotReuseTheKey()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); f.Media.LoseBegin = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request));
        Assert.Equal("Indeterminate", (await f.Db(db => db.MediaTransfers.SingleAsync())).State);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request));
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request with { ApprovalReference = "changed-plan" }));
        Assert.Equal(1, f.Media.Begins);
    }

    [Fact]
    public async Task LostChunkRequiresProbeOfTheSameSessionAndResumesOnlyFromConfirmedOffset()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(256 * 1024 + 17); f.Allow();
        var started = await f.Client().BeginMedia(id, request); f.Media.LoseChunk = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(started.TransferId, started.BindingHash, 0, new byte[256 * 1024]));
        Assert.Equal("ProbeRequired", (await f.Db(db => db.MediaTransfers.SingleAsync())).State);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(started.TransferId, started.BindingHash, 0, new byte[256 * 1024]));
        Assert.Equal(1, f.Media.Exchanges);
        f.Media.LoseChunk = false; var recovered = await f.Client().ProbeMedia(started.TransferId, started.BindingHash);
        Assert.Equal(256 * 1024, recovered.CommittedBytes);
        Assert.Equal("Completed", (await f.Client().MediaChunk(started.TransferId, started.BindingHash, recovered.CommittedBytes, new byte[17])).State);
        Assert.Equal(1, f.Media.Begins);
    }

    [Theory]
    [InlineData("offset")]
    [InlineData("binding")]
    [InlineData("transfer")]
    [InlineData("alignment")]
    [InlineData("too-long")]
    public async Task WrongContinuationCannotSendProviderBytes(string failure)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(256 * 1024 + 17); f.Allow();
        var start = await f.Client().BeginMedia(id, request);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(failure == "transfer" ? Guid.NewGuid() : start.TransferId,
            failure == "binding" ? new string('b', 64) : start.BindingHash, failure == "offset" ? 1 : 0,
            new byte[failure == "alignment" ? 16 : failure == "too-long" ? 512 * 1024 : 256 * 1024]));
        Assert.Equal(0, f.Media.Exchanges);
    }

    [Theory]
    [InlineData("external")]
    [InlineData("path")]
    [InlineData("userinfo")]
    public async Task InitiationRedirectCannotSubstituteAnotherCredentialDestination(string failure)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        f.Media.Location = failure switch { "external" => "https://other.example/steal", "path" => "https://www.googleapis.com/other",
            _ => "https://user:secret@www.googleapis.com/upload/youtube/v3/videos?private-session=1" };
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().BeginMedia(id, request)); Assert.Equal(0, f.Media.Exchanges);
        Assert.Equal("Indeterminate", (await f.Db(db => db.MediaTransfers.SingleAsync())).State);
    }

    [Fact]
    public async Task CancellationFencesAnInflightChunkWithoutClaimingRemoteDeletion()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        f.Media.AfterExchange = async () => Assert.Equal("Cancelled", (await f.Client().CancelMedia(start.TransferId, start.BindingHash)).State);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17]));
        var row = await f.Db(db => db.MediaTransfers.SingleAsync()); Assert.Equal("Cancelled", row.State); Assert.Empty(row.ProtectedSession);
        Assert.Equal(0, f.Provider.Revocations); Assert.Equal(1, f.Media.Begins);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().ProbeMedia(start.TransferId, start.BindingHash));
    }

    [Theory]
    [InlineData("disconnect")]
    [InlineData("policy")]
    [InlineData("package")]
    [InlineData("wrong-result-resource")]
    public async Task ChangedAuthorityOrResultResourceWithholdsCompletion(string change)
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow(); var start = await f.Client().BeginMedia(id, request);
        if (change == "wrong-result-resource") f.Media.WrongResultResource = true;
        else f.Media.AfterExchange = async () =>
        {
            if (change == "disconnect") await f.Client().Disconnect(id);
            else if (change == "policy") f.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies = [];
            else { await using var scope = f.Services.CreateAsyncScope(); await scope.ServiceProvider.GetRequiredService<RegistryService>().RevokePackage("operator", f.Digest, default); }
        };
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().MediaChunk(start.TransferId, start.BindingHash, 0, new byte[17]));
        Assert.False(await f.Db(db => db.Events.AnyAsync(x => x.Kind == "media.completed")));
        Assert.Empty((await f.Db(db => db.MediaTransfers.SingleAsync())).ProtectedResult);
    }

    [Fact]
    public async Task ExplicitSchemaUpgradeIsAdditiveAndExpiryClearsServiceOwnedSessionAndContent()
    {
        await using var f = new MediaFixture(); var (id, request) = await f.Ready(); f.Allow();
        var before = await f.Db(db => db.Connections.Select(x => x.ProtectedCredentials).SingleAsync());
        await f.Db(async db => { await db.Database.ExecuteSqlRawAsync("DROP TABLE MediaTransfers"); await db.Database.ExecuteSqlRawAsync("DELETE FROM __ConnectionSchema WHERE Version = '0.6.0'");
            await Assert.ThrowsAsync<InvalidOperationException>(() => ConnectionSchema.RequireCurrent(db)); await ConnectionSchema.Upgrade(db); await ConnectionSchema.Upgrade(db); await ConnectionSchema.RequireCurrent(db); return 0; });
        Assert.Equal(before, await f.Db(db => db.Connections.Select(x => x.ProtectedCredentials).SingleAsync()));
        var start = await f.Client().BeginMedia(id, request); f.Clock.Advance(TimeSpan.FromHours(1));
        await using (var scope = f.Services.CreateAsyncScope()) await scope.ServiceProvider.GetRequiredService<ManagedMediaService>().Expire(default);
        var expired = await f.Db(db => db.MediaTransfers.SingleAsync()); Assert.Equal("Expired", expired.State);
        Assert.Empty(expired.ProtectedSession); Assert.Empty(expired.ProtectedRequest); Assert.Empty(expired.ProtectedResult);
        await Assert.ThrowsAsync<HttpRequestException>(() => f.Client().ProbeMedia(start.TransferId, start.BindingHash));
    }

    private sealed class MediaFixture : ServiceFixture
    {
        public readonly FakeMedia Media = new();
        public readonly MediaSaves Saves = new();
        public readonly CachedReadRace Cached = new();
        public MediaFixture(bool resultBinding = true, string? unsupportedOutput = null, string? existingRoot = null, FakeMedia? existingProvider = null) : base(existingRoot)
        {
            if (existingProvider is not null) Media = existingProvider;
            Clock.BeforeRead = Cached.Inject;
            ManifestResource = "YouTubeConnector.0.2.2.json";
            ManifestTransform = source =>
            {
                if (resultBinding && unsupportedOutput is null) return source;
                var root = JsonNode.Parse(source)!;
                var mapping = root["providerOperations"]!.AsArray().Single(x => x!["capability"]!.GetValue<string>() == "youtube.api.video.upload.v1")!["http"]!;
                if (!resultBinding) mapping.AsObject().Remove("responseResourcePointers");
                if (unsupportedOutput is not null) foreach (var collection in new[] { "providerOperations", "provides" })
                {
                    var declaration = root[collection]!.AsArray().Single(x => x![collection == "providerOperations" ? "capability" : "name"]!.GetValue<string>() == "youtube.api.video.upload.v1")!;
                    declaration["outputSchema"]![unsupportedOutput] = unsupportedOutput == "allOf" ? new JsonArray(new JsonObject()) : new JsonObject();
                }
                return root.ToJsonString();
            };
        }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder); builder.ConfigureServices(services =>
            { services.RemoveAll<IProviderApiTransport>(); services.AddSingleton<IProviderApiTransport>(Media);
                services.RemoveAll<IProviderMediaTransport>(); services.AddSingleton<IProviderMediaTransport>(Media);
                services.AddDbContext<ConnectionStore>(o => o.AddInterceptors(Saves, new CachedCommands(Cached))); });
        }
        public void Allow() => Services.GetRequiredService<ServiceOptions>().ExecutionPolicies =
            [new() { DeploymentId = Deployment.DeploymentId, TenantId = Deployment.TenantId, PackageDigests = [Digest], AllowResumableMedia = true }];
        public async Task<(Guid, ManagedMediaRequest)> Ready(long size = 17, string[]? scopes = null)
        {
            await Initialize(); var begin = BeginRequest(scopes ?? ["base", "publishing"]); var (_, state, cookie) = await Launch(begin);
            var handoff = await Callback(state, cookie); var receipt = await Client().Redeem(new(handoff, ReturnVerifier, begin.LocalAttemptId, begin.ActorId, Digest));
            var id = receipt.ConnectionId!.Value; Assert.Equal("Ready", (await Client().Discover(id)).Status);
            var asset = Guid.NewGuid(); var input = JsonSerializer.SerializeToElement(new { mediaAssetId = asset.ToString("D"), title = "Synthetic private title", description = "Synthetic description",
                categoryId = "22", privacyStatus = "private", madeForKids = false, containsSyntheticMedia = false, notifySubscribers = false, idempotencyKey = "synthetic-idempotency" });
            return (id, new(new(Deployment.TenantId, begin.InstallationId, Guid.NewGuid(), Digest, "youtube.api.video.upload.v1", "channel-one", input, new string('a', 64), Clock.GetUtcNow().ToUnixTimeSeconds() + 30),
                "synthetic-idempotency", asset, new string('b', 64), size, "video/mp4", "synthetic-human-plan", Clock.GetUtcNow().AddMinutes(30).ToUnixTimeSeconds()));
        }
    }
    private sealed class CachedReadRace
    {
        private int profiles, target; private Action? action;
        public bool Injected;
        public void Arm(int profileReads, Action callback) { profiles = 0; target = profileReads; action = callback; Injected = false; }
        public void ProfileQuery() { if (action is not null && !Injected) profiles++; }
        public void Inject()
        {
            // Require reads the profile after its connection snapshot, then consults the
            // clock after that reader is fully consumed/disposed. Inject at that boundary,
            // without retaining a SQLite read lock or adding a production-only test hook.
            if (action is null || Injected || profiles < target) return;
            Injected = true; action();
        }
    }
    private sealed class CachedCommands(CachedReadRace race) : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData data,
            InterceptionResult<DbDataReader> result, CancellationToken ct = default)
        {
            if (command.CommandText.StartsWith("SELECT", StringComparison.Ordinal) && command.CommandText.Contains("FROM \"Profiles\"", StringComparison.Ordinal)) race.ProfileQuery();
            return ValueTask.FromResult(result);
        }
    }
    private sealed class MediaSaves : SaveChangesInterceptor
    {
        public bool FailCompletion; public Action? BeforeCompletion;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData data, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (data.Context!.ChangeTracker.Entries<ManagedMediaTransfer>().Any(x => x.State == EntityState.Modified && x.Entity.State == "Completed"))
            { BeforeCompletion?.Invoke(); if (FailCompletion) throw new DbUpdateException("Synthetic failed media commit"); }
            return ValueTask.FromResult(result);
        }
    }
    private sealed class FakeMedia : IProviderApiTransport, IProviderMediaTransport
    {
        public int Begins, Exchanges; public long Committed; public bool LoseBegin, LoseChunk, MultipleResources, WrongResultResource;
        public Func<Task>? AfterExchange, BeforeBegin;
        public string Location = "https://www.googleapis.com/upload/youtube/v3/videos?private-session=synthetic-secret";
        public Task<JsonElement> Read(Uri destination, string accessToken, CancellationToken ct)
        {
            Assert.Equal("secret-access-token", accessToken);
            return Task.FromResult(destination.AbsolutePath.Contains("userinfo", StringComparison.Ordinal)
                ? JsonSerializer.SerializeToElement(new { sub = "subject", name = "Account" })
                : JsonSerializer.SerializeToElement(new { items = (MultipleResources ? new[] { "channel-one", "channel-two" } : new[] { "channel-one" })
                    .Select(id => new { id, snippet = new { title = "Channel", customUrl = "@channel" } }).ToArray() }));
        }
        public async Task<ProviderMediaResponse> Exchange(ProviderMediaRequest request, string accessToken, CancellationToken ct)
        {
            Assert.Equal("secret-access-token", accessToken); Assert.Equal("www.googleapis.com", request.Destination.Host);
            Assert.Equal("/upload/youtube/v3/videos", request.Destination.AbsolutePath);
            if (request.Begin)
            {
                Begins++; using var metadata = JsonDocument.Parse(request.Body); Assert.Equal("private", metadata.RootElement.GetProperty("status").GetProperty("privacyStatus").GetString());
                if (BeforeBegin is not null) await BeforeBegin();
                Assert.DoesNotContain("mediaAssetId", metadata.RootElement.GetRawText());
                if (LoseBegin) throw new HttpRequestException("synthetic private provider failure");
                return new(201, Location, null, null, null);
            }
            Exchanges++; Assert.Contains("private-session=synthetic-secret", request.Destination.Query);
            if (!request.Probe) { Assert.Equal(Committed, request.Offset); Committed += request.Body.Length; }
            if (AfterExchange is not null) await AfterExchange();
            if (LoseChunk && !request.Probe) throw new HttpRequestException("synthetic private provider failure");
            return Committed < request.SizeBytes ? new(308, null, Committed, null, null)
                : new(200, null, null, JsonSerializer.SerializeToElement(new { id = "video-one01", snippet = new { channelId = WrongResultResource ? "channel-other" : "channel-one", title = "Video", categoryId = "22" },
                    status = new { privacyStatus = "private", uploadStatus = "uploaded" } }), null);
        }
    }
}
