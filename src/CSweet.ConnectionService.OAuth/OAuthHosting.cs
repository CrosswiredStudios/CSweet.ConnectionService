using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.RateLimiting;
using CSweet.ConnectionService;
using CSweet.ConnectionService.Protocol;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using CSweet.ConnectionService.Core;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;

namespace CSweet.ConnectionService;

public static class OAuthHosting
{
    public static void AddManagedOAuth(this WebApplicationBuilder builder)
    {
        var settings = builder.Configuration.GetSection(ServiceOptions.Section).Get<ServiceOptions>() ?? new();
        settings.Validate(builder.Environment.IsDevelopment());
        builder.Services.AddSingleton(settings); builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.Configure<ForwardedHeadersOptions>(o =>
        {
            o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto; o.ForwardLimit = 1;
            o.KnownIPNetworks.Clear(); o.KnownProxies.Clear();
            foreach (var address in settings.KnownProxyAddresses) o.KnownProxies.Add(IPAddress.Parse(address));
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Http.Result", LogLevel.Warning); // Redirect logging would disclose state/handoff URLs.
        builder.Logging.AddFilter("Microsoft.AspNetCore.Routing", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
        builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = ConnectionProtocol.MaximumBodyBytes);
        builder.Services.ConfigureHttpJsonOptions(o =>
        {
            o.SerializerOptions.PropertyNameCaseInsensitive = false;
            o.SerializerOptions.RespectNullableAnnotations = true;
            o.SerializerOptions.RespectRequiredConstructorParameters = true;
        });
        builder.Services.AddDbContext<ConnectionStore>(o => o.UseSqlite(settings.Database));
        var protection = builder.Services.AddDataProtection().SetApplicationName("CSweet.ConnectionService.v1")
            .PersistKeysToFileSystem(new DirectoryInfo(settings.KeyRingDirectory));
        if (!string.IsNullOrWhiteSpace(settings.ProtectionCertificatePath))
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(settings.ProtectionCertificatePath, settings.ProtectionCertificatePassword);
            using var privateKey = certificate.GetRSAPrivateKey();
            if (privateKey is null || privateKey.KeySize < 2048 || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
                throw new InvalidOperationException("A current RSA encryption certificate and its private key are required.");
            protection.ProtectKeysWithCertificate(certificate);
        }
        builder.Services.AddAuthentication();
        if (settings.EnableOidcAdministration) builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
        {
            o.Authority = settings.OperatorAuthority; o.Audience = settings.OperatorAudience; o.RequireHttpsMetadata = true;
            o.MapInboundClaims = false; o.SaveToken = false; o.IncludeErrorDetails = false;
            o.TokenValidationParameters.ValidateIssuer = true; o.TokenValidationParameters.ValidateAudience = true;
            o.TokenValidationParameters.ValidateLifetime = true; o.TokenValidationParameters.RequireExpirationTime = true;
            o.TokenValidationParameters.ValidateIssuerSigningKey = true; o.TokenValidationParameters.RequireSignedTokens = true;
            o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
        });
        builder.Services.AddAuthorization(o =>
        {
            o.AddPolicy("operator", p => p.RequireAuthenticatedUser().RequireClaim("csweet_role", "connection-service-operator").RequireAssertion(c => !string.IsNullOrWhiteSpace(c.User.FindFirst("sub")?.Value)));
            o.AddPolicy("enrollment", p => p.RequireAuthenticatedUser().RequireClaim("csweet_role", "enterprise-administrator", "connection-service-operator")
                .RequireAssertion(c => !string.IsNullOrWhiteSpace(c.User.FindFirst("sub")?.Value) && !string.IsNullOrWhiteSpace(c.User.FindFirst("csweet_tenant")?.Value)));
        });
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = 429;
            o.AddPolicy("bounded", context => RateLimitPartition.GetFixedWindowLimiter(context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 60, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
        });
        builder.Services.AddScoped<OwnerControl>(); builder.Services.AddScoped<LocalOwnerAdministration>();
        builder.Services.AddScoped<LocalProviderSetup>();
        builder.Services.AddScoped<CredentialVault>(); builder.Services.AddScoped<RegistryService>(); builder.Services.AddScoped<ConsentService>(); builder.Services.AddScoped<DeploymentAuthenticator>();
        builder.Services.AddSingleton<OAuthScopeConventions>();
        builder.Services.AddSingleton<IProviderOAuthTransport, PinnedProviderTransport>();
        builder.Services.AddSingleton<IProviderApiTransport, PinnedProviderTransport>();
        builder.Services.AddScoped<ConnectionCredentialService>(); builder.Services.AddScoped<ConnectionDiscoveryService>(); builder.Services.AddScoped<ConnectionRevocationService>();
        builder.Services.AddHostedService<ConnectionMaintenance>();
        builder.Services.AddSingleton<IConnectionModule, OAuthConnectionModule>();
    }
    public static async Task InitializeManagedOAuth(this WebApplication app, string[] args)
    {
        var settings = app.Services.GetRequiredService<ServiceOptions>();
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ConnectionStore>();
            if (app.Environment.IsDevelopment() && settings.InitializeDevelopmentStore || args.Contains("--initialize-store", StringComparer.Ordinal) || args.Contains("--migrate-store", StringComparer.Ordinal)) await ConnectionSchema.Upgrade(db);
            else if (!await db.Database.CanConnectAsync()) throw new InvalidOperationException("Initialize the managed connection store explicitly before starting.");
            await ConnectionSchema.RequireCurrent(db);
        }
    }
    public static void UseManagedOAuth(this WebApplication app)
    {
        if (app.Services.GetRequiredService<ServiceOptions>().KnownProxyAddresses.Length > 0) app.UseForwardedHeaders();
        app.Use(async (context, next) =>
        {
            OwnerFailureScope.Begin(context);
            context.Response.Headers.CacheControl = "no-store"; context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
            context.Response.Headers.XContentTypeOptions = "nosniff"; context.Response.Headers["X-CSweet-Connection-Protocol"] = ConnectionProtocol.Version;
            if (!context.Request.IsHttps) { context.Response.StatusCode = 400; OwnerFailureScope.Report(context, null); return; }
            try { await next(); }
            catch (Exception error) when (!context.Response.HasStarted && error is not OperationCanceledException)
            {
                context.Response.StatusCode = error switch
                {
                    UnauthorizedAccessException or CryptographicException => 403,
                    DbUpdateException => 409,
                    BadHttpRequestException b => b.StatusCode,
                    ArgumentException or InvalidOperationException or JsonException or FormatException or BadHttpRequestException => 400,
                    _ => 500
                };
                OwnerFailureScope.Report(context, error);
                await context.Response.WriteAsJsonAsync(new ServiceFailure(context.Response.StatusCode == 403 ? "connection_not_authorized" : context.Response.StatusCode == 409 ? "state_changed" : "connection_request_failed"));
            }
        });
        app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization();
        // Authenticate the exact bytes before endpoint binding consumes the request body.
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/v1"))
                context.Items["deployment"] = await context.RequestServices.GetRequiredService<DeploymentAuthenticator>().Authenticate(context, context.RequestAborted);
            await next();
        });
    }
}
public sealed class OAuthConnectionModule : IConnectionModule
{
    public string Kind => "oauth";
    public string Protocol => ConnectionProtocol.Version;
    public void MapEndpoints(IEndpointRouteBuilder app)
    {
        app.MapGet("/health", () => Results.Ok(new { status = "up", protocol = ConnectionProtocol.Version }));
        if (app.ServiceProvider.GetRequiredService<ServiceOptions>().EnableOidcAdministration)
        {
        var operators = app.MapGroup("/operator").RequireRateLimiting("bounded");
        operators.MapPost("/deployments", async (HttpContext c, EnrollDeployment r, RegistryService s, CancellationToken ct) => Results.Ok(await s.Enroll(c.User.FindFirst("csweet_tenant")!.Value, c.User.FindFirst("sub")!.Value, r, ct))).RequireAuthorization("enrollment");
        operators.MapPost("/deployments/{id:guid}/keys", async (Guid id, HttpContext c, RotateDeploymentKey r, RegistryService s, CancellationToken ct) => Results.Ok(await s.Rotate(c.User.FindFirst("csweet_tenant")!.Value, c.User.FindFirst("sub")!.Value, id, r, ct))).RequireAuthorization("enrollment");
        operators.MapPost("/deployments/{id:guid}/revoke", async (Guid id, HttpContext c, RegistryService s, CancellationToken ct) => { await s.Revoke(c.User.FindFirst("csweet_tenant")!.Value, c.User.FindFirst("sub")!.Value, id, ct); return Results.NoContent(); }).RequireAuthorization("enrollment");
        operators.MapPut("/profiles", async (HttpContext c, ConfigureProvider r, RegistryService s, CancellationToken ct) => Results.Ok(await s.Configure(c.User.FindFirst("sub")!.Value, r, ct))).RequireAuthorization("operator");
        operators.MapPost("/packages", async (HttpContext c, ApprovePackage r, RegistryService s, CancellationToken ct) => { await s.Approve(c.User.FindFirst("sub")!.Value, r, ct); return Results.NoContent(); }).RequireAuthorization("operator");
        operators.MapPost("/packages/{digest}/revoke", async (string digest, HttpContext c, RegistryService s, CancellationToken ct) => { await s.RevokePackage(c.User.FindFirst("sub")!.Value, digest, ct); return Results.NoContent(); }).RequireAuthorization("operator");
        operators.MapPost("/profiles/{id}/disable", async (string id, HttpContext c, RegistryService s, CancellationToken ct) => { await s.DisableProfile(c.User.FindFirst("sub")!.Value, id, ct); return Results.NoContent(); }).RequireAuthorization("operator");
        }
        app.MapGet("/service-info", (ServiceOptions o) => new ConnectionServiceCapabilities(o.PublicOrigin, ConnectionProtocol.Version, true, false, false));
        app.MapOwnerControl();
        var api = app.MapGroup("/v1").RequireRateLimiting("bounded");
        static Deployment DeploymentFor(HttpContext context) => (Deployment)context.Items["deployment"]!;
        api.MapGet("/deployment", (HttpContext c) => { var d = DeploymentFor(c); return Results.Ok(new DeploymentRegistration(d.Id, d.TenantId, d.Revision)); });
        api.MapGet("/packages/{digest}", async (string digest, RegistryService s, CancellationToken ct) => { var (_, _, profile) = await s.Resolve(digest, ct); return Results.Ok(s.Availability(profile)); });
        api.MapPost("/sessions", async (HttpContext c, BeginConnection r, ConsentService s, CancellationToken ct) => Results.Ok(await s.Begin(DeploymentFor(c), r, ct)));
        api.MapGet("/sessions/{id:guid}", async (Guid id, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.Attempt(DeploymentFor(c), id, ct)));
        api.MapPost("/sessions/{id:guid}/cancel", async (Guid id, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.Cancel(DeploymentFor(c), id, ct)));
        api.MapPost("/attempts/{id:guid}/cancel", async (Guid id, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.CancelAttempt(DeploymentFor(c), id, ct)));
        api.MapPost("/connections/{id:guid}/supersede/{replacement:guid}", async (Guid id, Guid replacement, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.Supersede(DeploymentFor(c), id, replacement, ct)));
        api.MapPost("/sessions/{id:guid}/receipt", async (Guid id, HttpContext c, RecoverConnection r, ConsentService s, CancellationToken ct) => Results.Ok(await s.Recover(DeploymentFor(c), id, r, ct)));
        api.MapPost("/handoffs/redeem", async (HttpContext c, RedeemConnection r, ConsentService s, CancellationToken ct) => Results.Ok(await s.Redeem(DeploymentFor(c), r, ct)));
        api.MapGet("/connections/{id:guid}", async (Guid id, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.Snapshot(DeploymentFor(c), id, ct)));
        api.MapPost("/connections/{id:guid}/inventory", async (Guid id, HttpContext c, ConnectionDiscoveryService s, CancellationToken ct) => Results.Ok(await s.Discover(DeploymentFor(c), id, ct)));
        api.MapPost("/connections/{id:guid}/disconnect", async (Guid id, HttpContext c, ConsentService s, CancellationToken ct) => Results.Ok(await s.Disconnect(DeploymentFor(c), id, ct)));
        api.MapGet("/events", async (long after, HttpContext c, ConnectionStore db, CancellationToken ct) =>
        {
            if (after < 0) throw new ArgumentException("Invalid event cursor."); var deployment = DeploymentFor(c);
            var rows = await db.Events.AsNoTracking().Where(x => x.DeploymentId == deployment.Id && x.Sequence > after).OrderBy(x => x.Sequence).Take(100).ToArrayAsync(ct);
            return Results.Ok(rows.Select(x => new ServiceEvent(x.Sequence, x.Id, x.Kind, x.ConnectionId, x.Revision, x.CreatedAt, x.SessionId)));
        });
        app.MapGet("/connect/{handle}", async (string handle, HttpContext c, ConsentService s, CancellationToken ct) =>
        {
            var start = await s.Launch(handle, ct);
            c.Response.Cookies.Append("__Host-csweet-oauth-" + start.SessionId.ToString("N"), start.BrowserBinding,
                new() { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/", MaxAge = TimeSpan.FromMinutes(10), IsEssential = true });
            return Results.Redirect(start.Url);
        }).RequireRateLimiting("bounded");
        app.MapGet("/oauth/callback/{profileId}", async (string profileId, HttpContext c, ConsentService s, CancellationToken ct) =>
        {
            var query = c.Request.Query;
            if (query["state"].Count != 1 || query["code"].Count > 1 || query["error"].Count > 1) throw new ArgumentException("Invalid callback.");
            var state = query["state"].ToString(); var id = s.IdentifyState(state, profileId); var cookie = "__Host-csweet-oauth-" + id.ToString("N");
            var result = await s.Complete(profileId, state, c.Request.Cookies[cookie], query["code"].FirstOrDefault(), query["error"].FirstOrDefault(), ct);
            c.Response.Cookies.Delete(cookie, new() { Secure = true, HttpOnly = true, Path = "/" }); return Results.Redirect(result.Url);
        }).RequireRateLimiting("bounded");
    }
}
