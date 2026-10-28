using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace CSweet.ConnectionService.Tests;

internal class ServiceFixture : WebApplicationFactory<Program>
{
    public const string Origin = "https://connections.example.com";
    public const string ReturnUri = "https://customer.example.com/api/plugin-connections/managed/return";
    public readonly string Root = Path.Combine(Path.GetTempPath(), "csweet-connections-tests", Guid.NewGuid().ToString("N"));
    public ServiceFixture(string? existingRoot = null) { if (existingRoot is not null) Root = existingRoot; }
    public readonly RSA SigningKey = RSA.Create(2048);
    public readonly ECDsa DeploymentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public readonly FakeProvider Provider = new(); public readonly MutableClock Clock = new();
    public readonly CapturedLogs Logs = new();
    public HttpClient Http = null!; public DeploymentRegistration Deployment = null!; public string Manifest = ""; public string Digest = "";
    public string ReturnVerifier = DeploymentProofCodec.Random(); public string ProfileId = "";
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(Root);
        builder.UseEnvironment("Development");
        builder.UseSetting("ConnectionService:PublicOrigin", Origin);
        builder.UseSetting("ConnectionService:Database", "Data Source=" + Path.Combine(Root, "connections.db"));
        builder.UseSetting("ConnectionService:KeyRingDirectory", Path.Combine(Root, "keys"));
        builder.UseSetting("ConnectionService:OperatorAuthority", "https://operators.example.com");
        builder.UseSetting("ConnectionService:OperatorAudience", "managed-operators");
        builder.UseSetting("ConnectionService:InitializeDevelopmentStore", "true");
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<ILoggerProvider>(Logs);
            services.RemoveAll<IProviderOAuthTransport>(); services.AddSingleton<IProviderOAuthTransport>(Provider);
            services.RemoveAll<TimeProvider>(); services.AddSingleton<TimeProvider>(Clock);
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
            {
                var oidc = new OpenIdConnectConfiguration { Issuer = "https://operators.example.com" }; oidc.SigningKeys.Add(new RsaSecurityKey(SigningKey));
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(oidc);
            });
        });
    }
    public HttpClient NewClient() => CreateClient(new() { BaseAddress = new(Origin), AllowAutoRedirect = false, HandleCookies = false });
    public string Token(string role = "connection-service-operator", string tenant = "tenant-a", string audience = "managed-operators")
    {
        var jwt = new JwtSecurityToken("https://operators.example.com", audience,
            [new("sub", "operator-1"), new("csweet_role", role), new("csweet_tenant", tenant)], DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(20),
            new SigningCredentials(new RsaSecurityKey(SigningKey), SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
    public async Task Initialize(bool secondProvider = false)
    {
        Http = NewClient(); Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token());
        using var stream = typeof(ServiceFixture).Assembly.GetManifestResourceStream("YouTubeConnector.0.2.1.json")!;
        Manifest = await new StreamReader(stream).ReadToEndAsync();
        if (secondProvider) Manifest = Manifest.Replace("youtube", "workspace", StringComparison.Ordinal).Replace("google", "example", StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(Manifest); var connection = doc.RootElement.GetProperty("connections")[0];
        ProfileId = connection.GetProperty("providerProfile").GetString()!; var provider = connection.GetProperty("provider");
        var config = new ConfigureProvider(ProfileId, "managed-client-id", provider.GetProperty("authorizationEndpoint").GetString()!, provider.GetProperty("tokenEndpoint").GetString()!, provider.GetProperty("revocationEndpoint").GetString()!, "application-secret");
        var configured = await Http.PutAsJsonAsync("/operator/profiles", config); configured.EnsureSuccessStatusCode();
        Digest = DeploymentProofCodec.Hash("reviewed-package:" + Manifest);
        var approved = await Http.PostAsJsonAsync("/operator/packages", new ApprovePackage(Digest, DeploymentProofCodec.Hash(Manifest), Manifest, ProfileId, 1, "https://github.com/example/connector", new string('a', 40)));
        approved.EnsureSuccessStatusCode();
        var enrollment = await Http.PostAsJsonAsync("/operator/deployments", new EnrollDeployment("Customer instance", DeploymentProofCodec.Encode(DeploymentKey.ExportSubjectPublicKeyInfo()), "key-1", [ReturnUri]));
        enrollment.EnsureSuccessStatusCode(); Deployment = (await enrollment.Content.ReadFromJsonAsync<DeploymentRegistration>())!;
    }
    public BeginConnection BeginRequest(string[]? sets = null)
    {
        using var json = JsonDocument.Parse(Manifest); var root = json.RootElement;
        return new(Guid.NewGuid(), Guid.NewGuid(), "human-correlation", Digest, root.GetProperty("accounts").GetProperty("connection").GetString()!, sets ?? ["base"],
            root.GetProperty("accounts").GetProperty("policyVersion").GetString()!, true, ReturnUri, DeploymentProofCodec.Challenge(ReturnVerifier));
    }
    public ManagedConnectionClient Client() => new(Http, new(Origin), Deployment.DeploymentId, "key-1", Deployment.Revision, DeploymentKey, Clock);
    public HttpRequestMessage Signed(string path, object? body = null, DeploymentProof? overrideProof = null, ECDsa? key = null)
    {
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, DeploymentProofCodec.Json); var now = Clock.GetUtcNow().ToUnixTimeSeconds();
        var proof = overrideProof ?? new DeploymentProof(Deployment.DeploymentId, "key-1", Origin, body is null ? "GET" : "POST", path, DeploymentProofCodec.Hash(bytes), now, now + 30, DeploymentProofCodec.Random(), Deployment.Revision);
        var message = new HttpRequestMessage(new HttpMethod(proof.Method), path);
        message.Headers.Add(ConnectionProtocol.ProofHeader, DeploymentProofCodec.Sign(proof, key ?? DeploymentKey));
        if (body is not null) { message.Content = new ByteArrayContent(bytes); message.Content.Headers.ContentType = new("application/json"); }
        return message;
    }
    public async Task<T> Db<T>(Func<ConnectionStore, Task<T>> action)
    { await using var scope = Services.CreateAsyncScope(); return await action(scope.ServiceProvider.GetRequiredService<ConnectionStore>()); }
    public async Task<(ConnectionAttempt Attempt, string State, string Cookie)> Launch(BeginConnection? request = null)
    {
        var attempt = await Client().Begin(request ?? BeginRequest());
        using var response = await Http.GetAsync(attempt.LaunchUrl); Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("S256", query["code_challenge_method"].ToString()); Assert.False(query.ContainsKey("client_secret"));
        var cookie = response.Headers.GetValues("Set-Cookie").Single().Split(';')[0];
        Provider.ExpectedChallenge = query["code_challenge"].ToString();
        return (attempt, query["state"].ToString(), cookie);
    }
    public async Task<string> Callback(string state, string cookie, string? error = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth/callback/" + ProfileId + "?state=" + Uri.EscapeDataString(state) + (error is null ? "&code=one-time-code" : "&error=" + error));
        request.Headers.Add("Cookie", cookie);
        using var response = await Http.SendAsync(request); Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(ReturnUri, response.Headers.Location!.GetLeftPart(UriPartial.Path));
        Assert.Equal("", response.Headers.Location.Query);
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(response.Headers.Location.Fragment[1..])["handoff"].ToString();
    }
}
internal sealed class CapturedLogs : ILoggerProvider
{
    public readonly ConcurrentQueue<string> Messages = new();
    public ILogger CreateLogger(string categoryName) => new Capture(Messages);
    public void Dispose() { }
    private sealed class Capture(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
    }
}
internal sealed class MutableClock : TimeProvider
{
    private DateTimeOffset now = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => now;
    public void Advance(TimeSpan amount) => now += amount;
}
internal sealed class FakeProvider : IProviderOAuthTransport
{
    public string? ExpectedChallenge; public int Exchanges; public string[]? GrantedScopes; public bool Fail;
    public Func<Task>? BeforeReceipt;
    public int Refreshes, Revocations;
    public Exception? RevocationFailure;
    public Action? BeforeRevocation;
    public bool FailRefresh;
    public string[]? RefreshScopes;
    public Task<ProviderTokenReceipt> Refresh(ProviderProfile profile, string secret, string token, CancellationToken ct)
    {
        Refreshes++;
        return FailRefresh ? Task.FromException<ProviderTokenReceipt>(new HttpRequestException("provider-secret-content"))
            : Task.FromResult(new ProviderTokenReceipt("refreshed-access", "rotated-refresh", 3600, RefreshScopes));
    }
    public Task<bool> Revoke(ProviderProfile profile, string secret, string token, CancellationToken ct)
    { Revocations++; BeforeRevocation?.Invoke(); ct.ThrowIfCancellationRequested(); return RevocationFailure is { } failure ? Task.FromException<bool>(failure) : Task.FromResult(true); }
    public async Task<ProviderTokenReceipt> Exchange(ProviderProfile profile, string secret, string code, string verifier, string callback, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); Exchanges++;
        Assert.Equal("application-secret", secret); Assert.Equal("one-time-code", code); Assert.Equal(ExpectedChallenge, DeploymentProofCodec.Challenge(verifier));
        Assert.EndsWith("/oauth/callback/" + profile.Id, callback);
        if (BeforeReceipt is not null) await BeforeReceipt();
        if (Fail) throw new HttpRequestException("SECRET provider content must not leak");
        return new("secret-access-token", "secret-refresh-token", 3600, GrantedScopes);
    }
}
