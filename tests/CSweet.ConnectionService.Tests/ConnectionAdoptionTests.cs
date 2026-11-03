using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CSweet.ConnectionService.Tests;

public sealed class ConnectionAdoptionTests
{
    [Fact]
    public async Task CompatibleAdoptionPreservesConsentAndVaultBytesButChangesExactExecutionBinding()
    {
        await using var f=new F();var (id,r)=await f.Ready();var before=await f.Db(db=>db.Connections.AsNoTracking().SingleAsync());
        var calls=f.Api.Calls;var preview=await f.Client().PreviewAdoption(id,r);
        Assert.Equal(before.InstallationId,await f.Db(db=>db.Connections.Select(x=>x.InstallationId).SingleAsync()));
        var receipt=await f.Client().Adopt(id,new(r,preview.ReviewHash));
        Assert.Equal("Adopted",receipt.Outcome);Assert.Equal(r.TargetInstallationId,receipt.CurrentInstallationId);
        var after=await f.Db(db=>db.Connections.AsNoTracking().SingleAsync());
        Assert.Equal(before.ProtectedCredentials,after.ProtectedCredentials);Assert.Equal(before.ProtectedInventory,after.ProtectedInventory);
        Assert.Equal(before.SubjectHash,after.SubjectHash);Assert.Equal(before.GrantedScopeSetsJson,after.GrantedScopeSetsJson);
        Assert.Equal(before.ProfileRevision,after.ProfileRevision);Assert.Equal(before.ProfileId,after.ProfileId);
        Assert.Equal(r.TargetPackageDigest,after.PackageDigest);Assert.Equal(before.Revision+1,after.Revision);
        var original=await f.Db(db=>db.Sessions.AsNoTracking().SingleAsync());
        Assert.Equal(r.SourcePackageDigest,original.PackageDigest);Assert.Equal(r.SourceInstallationId,original.InstallationId);
        Assert.Equal(1,f.Provider.Exchanges);Assert.Equal(0,f.Provider.Refreshes);Assert.Equal(0,f.Provider.Revocations);Assert.Equal(calls,f.Api.Calls);
        Assert.Empty(f.Services.GetRequiredService<ServiceOptions>().ExecutionPolicies);
        Assert.Single(await f.Db(db=>db.Adoptions.ToArrayAsync()));
        Assert.Single(await f.Db(db=>db.Events.Where(x=>x.Kind=="connection.package-adopted").ToArrayAsync()));
        var repeat=await f.Client().Adopt(id,new(r,preview.ReviewHash));Assert.Equal(receipt,repeat);
        var recovered=await f.Client().Adoption(r.AdoptionId);Assert.True(recovered.Found);Assert.Equal(receipt,recovered.Receipt);
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().Adopt(id,new(r with{TargetInstallationId=Guid.NewGuid()},preview.ReviewHash)));
        // Original consent cancellation still fences the adopted connection; no new consent is invented.
        await f.Client().CancelAttempt(original.LocalAttemptId);
        Assert.NotEqual("Ready",(await f.Client().Adoption(r.AdoptionId)).Receipt!.CurrentStatus);
    }

    [Theory]
    [InlineData("actor")][InlineData("consent-session")][InlineData("installation")][InlineData("package")][InlineData("profile-binding")]
    [InlineData("revision")][InlineData("status")][InlineData("inventory")][InlineData("lease")]
    [InlineData("media")][InlineData("target-package")][InlineData("target-installation")]
    public async Task InvalidOrChangedAuthorityCannotAdopt(string change)
    {
        await using var f=new F();var (id,r)=await f.Ready();var preview=await f.Client().PreviewAdoption(id,r);
        if(change=="actor")r=r with{ActorId="someone-else"};
        if(change=="consent-session")r=r with{OriginalConsentSessionId=Guid.NewGuid()};
        if(change=="installation")r=r with{SourceInstallationId=Guid.NewGuid()};
        if(change=="package")r=r with{SourcePackageDigest=new string('d',64)};
        if(change=="profile-binding")r=r with{ExpectedProfileBinding=new string('e',64)};
        await f.Db(async db=>
        {
            var c=await db.Connections.SingleAsync();
            if(change=="revision")c.Revision++;
            if(change=="status"){c.Status="RevocationPending";c.Revision++;}
            if(change=="inventory")c.InventoryVerifiedAt=f.Clock.GetUtcNow().AddDays(-2);
            if(change=="lease")c.LeaseOwner=Guid.NewGuid();
            if(change=="media")db.MediaTransfers.Add(new(){Id=Guid.NewGuid(),DeploymentId=f.Deployment.DeploymentId,ConnectionId=id,IdempotencyHash="active",State="Starting"});
            if(change=="target-package")(await db.Packages.SingleAsync(x=>x.Digest==r.TargetPackageDigest)).Revoked=true;
            if(change=="target-installation")db.Connections.Add(new(){Id=Guid.NewGuid(),DeploymentId=f.Deployment.DeploymentId,InstallationId=r.TargetInstallationId});
            return await db.SaveChangesAsync();
        });
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().Adopt(id,new(r,preview.ReviewHash)));
        Assert.Empty(await f.Db(db=>db.Adoptions.ToArrayAsync()));
        Assert.Empty(await f.Db(db=>db.Events.Where(x=>x.Kind=="connection.package-adopted").ToArrayAsync()));
        Assert.Equal(0,f.Provider.Refreshes);Assert.Equal(0,f.Provider.Revocations);
    }

    [Theory]
    [InlineData("scope-definition")][InlineData("permission")][InlineData("read-endpoint")][InlineData("read-output")]
    [InlineData("identity")][InlineData("lifecycle")][InlineData("publisher")]
    public async Task SemanticChangesUnderUnchangedIdsAreNotCompatible(string change)
    {
        await using var f=new F();var (id,r)=await f.Ready();
        await f.Db(async db=>
        {
            var package=await db.Packages.SingleAsync(x=>x.Digest==r.TargetPackageDigest);var root=JsonNode.Parse(package.ManifestJson)!;
            if(change=="scope-definition")root["connections"]![0]!["scopeSets"]![0]!["scopes"]!.AsArray().Add("new-scope");
            if(change=="permission")root["accounts"]!["permissions"]![0]!["purpose"]="Changed policy";
            if(change=="read-endpoint")root["providerOperations"]!.AsArray().First(x=>x!["capability"]!.GetValue<string>()=="youtube.api.channel.read.v1")!["http"]!["queryConstants"]!["part"]="id";
            if(change=="read-output")root["providerOperations"]!.AsArray().First(x=>x!["capability"]!.GetValue<string>()=="youtube.api.channel.read.v1")!["outputSchema"]!["additionalProperties"]=true;
            if(change=="identity")root["accounts"]!["identity"]!["subjectPointer"]="/other";
            if(change=="lifecycle")root["accounts"]!["policyVersion"]="changed";
            if(change=="publisher")root["publisher"]!["id"]="com.other";
            package.ManifestJson=root.ToJsonString();return await db.SaveChangesAsync();
        });
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().PreviewAdoption(id,r));
        Assert.Empty(await f.Db(db=>db.Adoptions.ToArrayAsync()));Assert.Equal(0,f.Provider.Revocations);
    }

    [Fact]
    public async Task AlreadyGrantedWriteScopeMakesChangedWriteMappingIncompatible()
    {await using var f=new F();var(id,r)=await f.Ready(["base","publishing"]);await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().PreviewAdoption(id,r));}

    [Fact]
    public async Task AdoptionUsesTheExistingDeclaredAuthorizationWindowWithoutRefreshingOrExtendingCredentials()
    {
        await using var f=new F();var(id,r)=await f.Ready();var before=await f.Db(db=>db.Connections.Select(x=>x.ProtectedCredentials).SingleAsync());
        f.Clock.Advance(TimeSpan.FromHours(2));var p=await f.Client().PreviewAdoption(id,r);await f.Client().Adopt(id,new(r,p.ReviewHash));
        Assert.Equal(before,await f.Db(db=>db.Connections.Select(x=>x.ProtectedCredentials).SingleAsync()));Assert.Equal(0,f.Provider.Refreshes);
    }

    [Fact]
    public async Task CancellationTombstonePreventsLateAdoptionWithoutRevokingConsent()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);
        var cancelled=await f.Client().CancelAdoption(id,r);Assert.Equal("Cancelled",cancelled.Outcome);
        Assert.Equal("Ready",cancelled.CurrentStatus);Assert.Equal(r.SourceInstallationId,cancelled.CurrentInstallationId);
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().Adopt(id,new(r,p.ReviewHash)));
        Assert.Equal(cancelled,(await f.Client().Adoption(r.AdoptionId)).Receipt);Assert.Equal(0,f.Provider.Revocations);
        Assert.Equal(cancelled,await f.Client().CancelAdoption(id,r));
    }

    [Fact]
    public async Task FailedAtomicSaveLeavesSourceAuthorityAndNoReceiptOrAuditThenSameIntentCanRecover()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);f.Saves.Fail=true;
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().Adopt(id,new(r,p.ReviewHash)));
        Assert.Equal(r.SourceInstallationId,await f.Db(db=>db.Connections.Select(x=>x.InstallationId).SingleAsync()));
        Assert.False((await f.Client().Adoption(r.AdoptionId)).Found);
        Assert.Empty(await f.Db(db=>db.Events.Where(x=>x.Kind=="connection.package-adopted").ToArrayAsync()));
        Assert.Equal("Adopted",(await f.Client().Adopt(id,new(r,p.ReviewHash))).Outcome);
    }

    [Fact]
    public async Task AdoptionReceiptsAreImmutableInEfAndSqlAndNotVisibleToAnotherDeployment()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);await f.Client().Adopt(id,new(r,p.ReviewHash));
        await f.Db(async db=>{var row=await db.Adoptions.SingleAsync();row.Outcome="Cancelled";await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());return 0;});
        await f.Db(async db=>{await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(()=>db.Database.ExecuteSqlRawAsync("DELETE FROM Adoptions"));return 0;});
        var second=await f.Http.PostAsJsonAsync("/operator/deployments",new EnrollDeployment("second",DeploymentProofCodec.Encode(f.DeploymentKey.ExportSubjectPublicKeyInfo()),"key-1",[ServiceFixture.ReturnUri]));
        second.EnsureSuccessStatusCode();var registration=(await second.Content.ReadFromJsonAsync<DeploymentRegistration>())!;
        var other=new ManagedConnectionClient(f.Http,new(ServiceFixture.Origin),registration.DeploymentId,"key-1",registration.Revision,f.DeploymentKey,f.Clock);
        Assert.False((await other.Adoption(r.AdoptionId)).Found);
        await Assert.ThrowsAsync<HttpRequestException>(()=>other.PreviewAdoption(id,r));
    }

    [Fact]
    public async Task AdoptionDoesNotAuthorizeEitherOldOrNewExecutionAndOldBindingCannotBeReused()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);var calls=f.Api.Calls;
        await f.Client().Adopt(id,new(r,p.ReviewHash));
        var operation=new ManagedReadRequest(f.Deployment.TenantId,r.SourceInstallationId,Guid.NewGuid(),r.SourcePackageDigest,
            "youtube.api.channel.read.v1","channel-one",JsonSerializer.SerializeToElement(new{}),new string('a',64),f.Clock.GetUtcNow().ToUnixTimeSeconds()+30);
        var options=f.Services.GetRequiredService<ServiceOptions>();options.ExecutionPolicies=[new(){DeploymentId=f.Deployment.DeploymentId,
            TenantId=f.Deployment.TenantId,PackageDigests=[r.SourcePackageDigest],AllowReads=true}];
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().ReadOperation(id,operation));
        operation=operation with{InstallationId=r.TargetInstallationId,PackageDigest=r.TargetPackageDigest};
        await Assert.ThrowsAsync<HttpRequestException>(()=>f.Client().ReadOperation(id,operation));Assert.Equal(calls,f.Api.Calls);
        options.ExecutionPolicies=[new(){DeploymentId=f.Deployment.DeploymentId,TenantId=f.Deployment.TenantId,PackageDigests=[r.TargetPackageDigest],AllowReads=true}];
        Assert.Equal(id,(await f.Client().ReadOperation(id,operation)).ConnectionId);
    }

    [Fact]
    public async Task ConcurrentDistinctTargetsHaveOneWinnerAndReplayProofCannotResubmit()
    {
        await using var f=new F();var(id,r)=await f.Ready();var other=r with{AdoptionId=Guid.NewGuid(),TargetInstallationId=Guid.NewGuid()};
        var p=await f.Client().PreviewAdoption(id,r);var q=await f.Client().PreviewAdoption(id,other);
        var path=$"/v1/connections/{id:D}/adoptions";using var first=f.Signed(path,new ApproveConnectionAdoption(r,p.ReviewHash));
        var proof=first.Headers.GetValues(ConnectionProtocol.ProofHeader).Single();using var second=f.Signed(path,new ApproveConnectionAdoption(other,q.ReviewHash));
        var replies=await Task.WhenAll(f.Http.SendAsync(first),f.Http.SendAsync(second));
        Assert.Single(replies,x=>x.StatusCode==HttpStatusCode.OK);Assert.Single(replies,x=>x.StatusCode==HttpStatusCode.Forbidden);
        foreach(var reply in replies)reply.Dispose();
        using var replay=f.Signed(path,new ApproveConnectionAdoption(r,p.ReviewHash));replay.Headers.Remove(ConnectionProtocol.ProofHeader);replay.Headers.Add(ConnectionProtocol.ProofHeader,proof);
        using var rejected=await f.Http.SendAsync(replay);Assert.Equal(HttpStatusCode.Forbidden,rejected.StatusCode);
        Assert.Single(await f.Db(db=>db.Adoptions.ToArrayAsync()));Assert.Single(await f.Db(db=>db.Events.Where(x=>x.Kind=="connection.package-adopted").ToArrayAsync()));
    }

    [Fact]
    public async Task ExplicitSchemaUpgradeAddsAdoptionReceiptsWithoutChangingExistingCredentialsOrConsents()
    {
        await using var f=new F();var(id,r)=await f.Ready();var before=await f.Db(db=>db.Connections.Select(x=>x.ProtectedCredentials).SingleAsync());
        await f.Db(async db=>{await db.Database.ExecuteSqlRawAsync("DROP TABLE Adoptions");await db.Database.ExecuteSqlRawAsync("DELETE FROM __ConnectionSchema WHERE Version = '0.7.0'");
            await Assert.ThrowsAsync<InvalidOperationException>(()=>ConnectionSchema.RequireCurrent(db));await ConnectionSchema.Upgrade(db);await ConnectionSchema.Upgrade(db);await ConnectionSchema.RequireCurrent(db);return 0;});
        Assert.Equal(before,await f.Db(db=>db.Connections.Select(x=>x.ProtectedCredentials).SingleAsync()));
        Assert.Equal(r.SourceInstallationId,await f.Db(db=>db.Connections.Select(x=>x.InstallationId).SingleAsync()));
        Assert.Equal(1,await f.Db(db=>db.Sessions.CountAsync()));Assert.Empty(await f.Db(db=>db.Adoptions.ToArrayAsync()));
    }

    [Fact]
    public async Task AdoptionValidationAndSaveHoldTheSameAuthorityWriteFence()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);var observed=false;
        f.Saves.Before=()=>
        {
            using var competing=new Microsoft.Data.Sqlite.SqliteConnection("Data Source="+Path.Combine(f.Root,"connections.db")+";Default Timeout=1");competing.Open();
            using(var limit=competing.CreateCommand()){limit.CommandText="PRAGMA busy_timeout=1";limit.ExecuteNonQuery();}
            using var command=competing.CreateCommand();command.CommandTimeout=1;command.CommandText="UPDATE Connections SET Status='RevocationPending', Revision=Revision+1 WHERE Id=$id";
            command.Parameters.AddWithValue("$id",id.ToString().ToUpperInvariant());
            var failure=Assert.Throws<Microsoft.Data.Sqlite.SqliteException>(()=>command.ExecuteNonQuery());Assert.Equal(5,failure.SqliteErrorCode);observed=true;
        };
        await f.Client().Adopt(id,new(r,p.ReviewHash));Assert.True(observed);
        await f.Db(async db=>{var current=await db.Connections.SingleAsync();current.Status="RevocationPending";current.Revision++;return await db.SaveChangesAsync();});
        Assert.Equal("RevocationPending",(await f.Client().Adoption(r.AdoptionId)).Receipt!.CurrentStatus);
    }

    [Fact]
    public async Task UnknownCallerFieldsAreRejectedWithoutProviderIoOrDiagnosticBodyDisclosure()
    {
        await using var f=new F();var(id,r)=await f.Ready();var p=await f.Client().PreviewAdoption(id,r);var calls=f.Api.Calls;
        var body=new{request=r,reviewHash=p.ReviewHash,extra="CANARY-synthetic-provider-proof"};
        using var rejected=await f.Http.SendAsync(f.Signed($"/v1/connections/{id:D}/adoptions",body));
        Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);Assert.Equal(calls,f.Api.Calls);
        Assert.DoesNotContain("CANARY",await rejected.Content.ReadAsStringAsync());Assert.DoesNotContain(f.Logs.Messages,x=>x.Contains("CANARY",StringComparison.Ordinal));
        Assert.Empty(await f.Db(db=>db.Adoptions.ToArrayAsync()));
    }

    private sealed class F:ServiceFixture
    {
        public readonly Api Api=new();public readonly AdoptionSaves Saves=new();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {base.ConfigureWebHost(builder);builder.ConfigureServices(s=>{s.RemoveAll<IProviderApiTransport>();s.AddSingleton<IProviderApiTransport>(Api);s.AddDbContext<ConnectionStore>(o=>o.AddInterceptors(Saves));});}
        public async Task<(Guid,ConnectionAdoptionRequest)> Ready(string[]? scopeSets=null)
        {
            await Initialize();var begin=BeginRequest(scopeSets);var(attempt,state,cookie)=await Launch(begin);var handoff=await Callback(state,cookie);
            var c=await Client().Redeem(new(handoff,ReturnVerifier,begin.LocalAttemptId,begin.ActorId,Digest));var id=c.ConnectionId!.Value;
            var inventory=await Client().Discover(id);Assert.Equal("Ready",inventory.Status);
            var root=JsonNode.Parse(Manifest)!;root["version"]="0.2.2";
            root["providerOperations"]!.AsArray().Single(x=>x!["capability"]!.GetValue<string>()=="youtube.api.video.upload.v1")!["http"]!["responseResourcePointers"]=new JsonArray("/snippet/channelId");
            var target=root.ToJsonString();var digest=DeploymentProofCodec.Hash("target:"+target);
            using var approved=await Http.PostAsJsonAsync("/operator/packages",new ApprovePackage(digest,DeploymentProofCodec.Hash(target),target,ProfileId,1,"https://github.com/example/connector",new string('b',40)));approved.EnsureSuccessStatusCode();
            return(id,new(Guid.NewGuid(),begin.InstallationId,Guid.NewGuid(),Digest,digest,inventory.Revision,(await Client().Availability(Digest)).BindingHash,begin.ActorId,attempt.SessionId));
        }
    }
    private sealed class Api:IProviderApiTransport
    {
        public int Calls;
        public Task<JsonElement> Read(Uri uri,string token,CancellationToken ct)
        {Calls++;return Task.FromResult(uri.AbsolutePath.Contains("userinfo",StringComparison.Ordinal)
            ?JsonSerializer.SerializeToElement(new{sub="subject-one",name="Synthetic account"})
            :JsonSerializer.SerializeToElement(new{items=new[]{new{id="channel-one",snippet=new{title="Synthetic channel",customUrl="@synthetic"}}}}));}
    }
    private sealed class AdoptionSaves:SaveChangesInterceptor
    {
        public bool Fail;public Action? Before;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData data,InterceptionResult<int> result,CancellationToken ct=default)
        {if(data.Context!.ChangeTracker.Entries<ManagedConnectionAdoption>().Any(x=>x.State==EntityState.Added))
            {Assert.NotNull(data.Context.Database.CurrentTransaction);Before?.Invoke();if(Fail){Fail=false;throw new InvalidOperationException("synthetic atomic-save failure");}}
            return ValueTask.FromResult(result);}
    }
}
