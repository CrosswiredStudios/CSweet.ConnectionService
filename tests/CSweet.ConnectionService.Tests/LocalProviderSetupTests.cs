using System.Text;
using System.Net.Http.Json;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Tests;

public class LocalProviderSetupTests
{
    private const string Profile = "com.csweet.google.youtube";
    private const string Secret = "synthetic-local-setup-secret";
    private static string File(ServiceFixture f, string name, string content)
    {
        var path = Path.Combine(f.Root, name); System.IO.File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows()) System.IO.File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }
    private static LocalSetupCommand Import(ServiceFixture f, long revision = 0, long secretVersion = 0, string? client = null)
    {
        var path = File(f, Guid.NewGuid()+".json", JsonSerializer.Serialize(new { web = new { client_id = client ?? "test-client",
            client_secret = Secret, project_id = "test-project", auth_uri = "https://accounts.google.com/o/oauth2/auth",
            token_uri = "https://oauth2.googleapis.com/token", redirect_uris = new[] { ServiceFixture.Origin+"/oauth/callback/"+Profile } } }));
        return new("import-credentials", ServiceFixture.Origin, new(Profile, "google-web-client", path, revision, secretVersion), null);
    }
    private static async Task<LocalSetupResult> Execute(ServiceFixture f, LocalSetupCommand c)
    {
        await using var scope = f.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<LocalProviderSetup>().Execute(c, default);
    }
    private static LocalSetupCommand Approval(ServiceFixture f, string? commit = null, long revision = 1)
    {
        using var stream = typeof(ServiceFixture).Assembly.GetManifestResourceStream("YouTubeConnector.0.2.1.json")!;
        var manifest = new StreamReader(stream).ReadToEnd(); var hash = DeploymentProofCodec.Hash(manifest);
        var repo = "https://github.com/example/connector"; commit ??= new string('a',40);
        var identity = JsonSerializer.SerializeToUtf8Bytes(new { format = "connector-declarations.v1", repository = repo, commit, manifest = hash });
        return new("approve-package", ServiceFixture.Origin, null, new(DeploymentProofCodec.Hash(identity), hash,
            File(f, Guid.NewGuid()+".json", manifest), Profile, revision, repo, commit));
    }
    [Fact]
    public async Task ImportEncryptsAndAuditsWithoutAnyRemoteAuthority()
    {
        await using var f = new ServiceFixture { OidcAdministration=false }; f.Http=f.NewClient();
        var result = await Execute(f, Import(f)); Assert.Equal(1,result.SecretVersion); Assert.True(result.Changed);
        Assert.DoesNotContain(Secret,JsonSerializer.Serialize(result));
        Assert.NotEqual(Secret,await f.Db(db=>db.Profiles.Select(x=>x.ProtectedSecret).SingleAsync()));
        Assert.Equal(1,await f.Db(db=>db.Events.CountAsync(x=>x.Kind=="profile.configured" && x.OperatorSubject=="local-os:"+Environment.UserName)));
        Assert.Equal(0,await f.Db(db=>db.OwnerGrants.CountAsync())); Assert.Equal(0,await f.Db(db=>db.Deployments.CountAsync()));
        Assert.Equal(System.Net.HttpStatusCode.Forbidden,(await f.Http.PostAsJsonAsync("/owner-control/v1/credentials/import",new {})).StatusCode);
    }
    [Fact]
    public async Task ImportRequiresBothCurrentVersionsAndRejectsChangedIdentity()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient(); await Execute(f,Import(f));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Execute(f,Import(f)));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Execute(f,Import(f,1,2)));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Execute(f,Import(f,1,1,"different-client")));
        var rotated=await Execute(f,Import(f,1,1));Assert.Equal(2,rotated.SecretVersion);
        Assert.Equal(2,await f.Db(db=>db.Events.CountAsync(x=>x.Kind=="profile.configured")));
    }
    [Fact]
    public async Task ConcurrentImportsHaveOnlyOneWinner()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();var a=Import(f);var b=Import(f);
        async Task<bool> Try(LocalSetupCommand c) { try { await Execute(f,c);return true;} catch(InvalidOperationException){return false;} }
        var results=await Task.WhenAll(Task.Run(()=>Try(a)),Task.Run(()=>Try(b)));
        Assert.Single(results,x=>x);Assert.Equal(1,await f.Db(db=>db.Events.CountAsync(x=>x.Kind=="profile.configured")));
    }
    [Fact]
    public async Task AuditFailureRollsBackProfile()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();
        await f.Db(db=>db.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_setup_audit BEFORE INSERT ON Events BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END;"));
        await Assert.ThrowsAsync<DbUpdateException>(()=>Execute(f,Import(f)));
        Assert.Equal(0,await f.Db(db=>db.Profiles.CountAsync()));
    }
    [Fact]
    public async Task ApprovalIsIdempotentAndRejectsRevokedOrStaleBindings()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();await Execute(f,Import(f));var c=Approval(f);
        Assert.True((await Execute(f,c)).Changed);Assert.False((await Execute(f,c)).Changed);
        Assert.Equal(1,await f.Db(db=>db.Events.CountAsync(x=>x.Kind=="package.approved")));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Execute(f,Approval(f,revision:2)));
        await f.Db(db=>db.Packages.ExecuteUpdateAsync(x=>x.SetProperty(p=>p.Revoked,true)));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Execute(f,c));
    }
    [Fact]
    public async Task ApprovalRejectsManifestOrDeclarationDigestMismatch()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();await Execute(f,Import(f));var c=Approval(f);
        await Assert.ThrowsAsync<ArgumentException>(()=>Execute(f,c with {PackageApproval=c.PackageApproval! with {PackageDigest=new string('b',64)}}));
        await Assert.ThrowsAsync<ArgumentException>(()=>Execute(f,c with {PackageApproval=c.PackageApproval! with {ManifestSha256=new string('b',64)}}));
        Assert.Equal(0,await f.Db(db=>db.Packages.CountAsync()));
    }
    [Fact]
    public async Task ApprovalAuditFailureRollsBackPackage()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();await Execute(f,Import(f));
        await f.Db(db=>db.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_package_audit BEFORE INSERT ON Events BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END;"));
        await Assert.ThrowsAsync<DbUpdateException>(()=>Execute(f,Approval(f)));
        Assert.Equal(0,await f.Db(db=>db.Packages.CountAsync()));
    }
    [Theory]
    [InlineData("{\"action\":\"grant\",\"tenantScope\":\"*\"}")]
    [InlineData("{\"action\":\"import-credentials\",\"action\":\"approve-package\"}")]
    [InlineData("{\"action\":\"import-credentials\",\"serviceOrigin\":\"x\",\"credentialImport\":null,\"packageApproval\":null}")]
    [InlineData("{\"action\":\"import-credentials\",\"credentialImport\":{\"capabilities\":[\"credentials.import\"]}}")]
    public void RejectsUnknownScopesActionsAndDuplicates(string json) => Assert.ThrowsAny<Exception>(()=>LocalSetupCommand.Parse(Encoding.UTF8.GetBytes(json)));
    [Fact]
    public async Task WrongOriginUnknownFormatAndNegativeVersionsDoNotMutate()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();var c=Import(f);
        await Assert.ThrowsAsync<ArgumentException>(()=>Execute(f,c with {ServiceOrigin="https://other.example.com"}));
        await Assert.ThrowsAsync<ArgumentException>(()=>Execute(f,c with {CredentialImport=c.CredentialImport! with {Format="unknown"}}));
        await Assert.ThrowsAsync<ArgumentException>(()=>Execute(f,Import(f,-1,-1)));
        Assert.Equal(0,await f.Db(db=>db.Profiles.CountAsync()));
    }
    [Fact]
    public async Task FileInputRejectsRelativeOversizedAndUnixPublicOrSymlinkFiles()
    {
        await using var f=new ServiceFixture();f.Http=f.NewClient();
        await Assert.ThrowsAsync<ArgumentException>(()=>LocalSetupFiles.Read("relative.json",100,default));
        var path=File(f,"input.json",new string('a',101));
        await Assert.ThrowsAsync<ArgumentException>(()=>LocalSetupFiles.Read(path,100,default));
        if(!OperatingSystem.IsWindows())
        {
            System.IO.File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.OtherRead);
            await Assert.ThrowsAsync<ArgumentException>(()=>LocalSetupFiles.Read(path,200,default));
            var link=Path.Combine(f.Root,"link.json");System.IO.File.CreateSymbolicLink(link,path);
            await Assert.ThrowsAsync<ArgumentException>(()=>LocalSetupFiles.Read(link,200,default));
        }
    }
    [Fact]
    public async Task RealCliUsesProductionFilesAndKeepsSuccessAndFailureOutputSecretSafe()
    {
        await using var f=new ServiceFixture {OidcAdministration=false}; f.Http=f.NewClient();
        using var rsa=System.Security.Cryptography.RSA.Create(2048);
        var request=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Disposable setup test",rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
        var certificate=Path.Combine(f.Root,"test-protection.pfx");
        System.IO.File.WriteAllBytes(certificate,cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx));
        if(!OperatingSystem.IsWindows()) System.IO.File.SetUnixFileMode(certificate,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        File(f,"appsettings.Production.json",JsonSerializer.Serialize(new {ConnectionService=new {
            PublicOrigin=ServiceFixture.Origin,Database="Data Source="+Path.Combine(f.Root,"connections.db"),
            KeyRingDirectory=Path.Combine(f.Root,"keys"),ProtectionCertificatePath=certificate,
            EnableOidcAdministration=false,InitializeDevelopmentStore=false}}));
        var command=Import(f);
        var commandPath=File(f,"setup.json",JsonSerializer.Serialize(command,DeploymentProofCodec.Json));
        async Task<(int Exit,string Out,string Error)> Run(params string[] extra)
        {
            var start=new System.Diagnostics.ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ??
                Path.Combine(Environment.GetEnvironmentVariable("DOTNET_ROOT")!,OperatingSystem.IsWindows()?"dotnet.exe":"dotnet"))
                {RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
            start.ArgumentList.Add(typeof(Program).Assembly.Location);
            start.ArgumentList.Add("--local-setup");start.ArgumentList.Add(commandPath);
            start.ArgumentList.Add("--contentRoot");start.ArgumentList.Add(f.Root);
            foreach(var arg in extra) start.ArgumentList.Add(arg);
            start.Environment["ASPNETCORE_ENVIRONMENT"]="Production";start.Environment["DOTNET_ENVIRONMENT"]="Production";
            using var process=System.Diagnostics.Process.Start(start)!;
            var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try {await process.WaitForExitAsync(timeout.Token);} catch {process.Kill(entireProcessTree:true);throw;}
            return(process.ExitCode,await stdout,await stderr);
        }
        var success=await Run();Assert.Equal(0,success.Exit);Assert.Empty(success.Error);
        Assert.DoesNotContain(Secret,success.Out);Assert.Contains("import-credentials",success.Out);
        var duplicate=await Run();Assert.Equal(1,duplicate.Exit);Assert.Empty(duplicate.Out);
        Assert.Contains("Local provider setup failed.",duplicate.Error);Assert.DoesNotContain(Secret,duplicate.Error);
        var forbidden=await Run("--migrate-store","true");Assert.Equal(1,forbidden.Exit);Assert.Empty(forbidden.Out);
        Assert.Equal(1,await f.Db(db=>db.Events.CountAsync(x=>x.Kind=="profile.configured")));
    }

}
