using System.Net;
using System.Security.Cryptography;
using System.Text;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Tests;

public sealed class OwnerDiagnosticTests
{
    [Fact]
    public async Task InvalidSignatureDoesNotExposeBindingOrCryptographicStageInPublicHint()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var owner = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var actor = Guid.NewGuid();
        await using var scope = f.Services.CreateAsyncScope();
        var registration = (OwnerRegistration)await scope.ServiceProvider.GetRequiredService<LocalOwnerAdministration>().Execute(
            new("bootstrap", ServiceFixture.Origin, Guid.NewGuid(), DeploymentProofCodec.Encode(owner.ExportSubjectPublicKeyInfo()), "owner", actor, "tenant-a", [OwnerProtocol.Enroll], 0), default);
        var error = await Assert.ThrowsAsync<OwnerOperationException>(() => new OwnerAdministrationClient(f.Http, registration, wrong, f.Clock).Access(actor));
        Assert.Equal(HttpStatusCode.Forbidden, error.StatusCode);
        Assert.Equal("authorization", error.Diagnostic!.Stage);
        Assert.Equal("UnauthorizedAccessException", error.Diagnostic.ExceptionType);
        Assert.Contains(f.Logs.Messages, x => x.Contains("exceptionType=CryptographicException", StringComparison.Ordinal));
        Assert.Equal(0, await f.Db(db => db.OwnerNonces.CountAsync()));
    }
    [Fact]
    public async Task ValidationFailureHasSafeHintsAndRollsBackNonceDeploymentAndEvents()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var owner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var actor = Guid.NewGuid();
        await using var scope = f.Services.CreateAsyncScope();
        var registration = (OwnerRegistration)await scope.ServiceProvider.GetRequiredService<LocalOwnerAdministration>().Execute(
            new("bootstrap", ServiceFixture.Origin, Guid.NewGuid(), DeploymentProofCodec.Encode(owner.ExportSubjectPublicKeyInfo()), "owner", actor, "tenant-a", [OwnerProtocol.Enroll], 0), default);
        var client = new OwnerAdministrationClient(f.Http, registration, owner, f.Clock);
        using var customer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string sensitive = "MUST_NOT_APPEAR_CREDENTIAL_BODY";
        var request = new OwnerEnrollment("tenant-a", new(sensitive + new string('x', 201), DeploymentProofCodec.Encode(customer.ExportSubjectPublicKeyInfo()), "customer", [ServiceFixture.ReturnUri]));
        var error = await Assert.ThrowsAsync<OwnerOperationException>(() => client.Enroll(actor, 1, request));
        Assert.Equal(HttpStatusCode.BadRequest, error.StatusCode);
        Assert.NotNull(error.Diagnostic); Assert.Equal("name", error.Diagnostic.Stage);
        Assert.Equal("ArgumentException", error.Diagnostic.ExceptionType);
        Assert.Equal("request_rejected", error.Diagnostic.Code);
        Assert.Matches("^[a-f0-9]{32}$", error.Diagnostic.CorrelationId);
        Assert.InRange(error.Diagnostic.ElapsedMilliseconds, 0, OwnerFailureDiagnostic.MaximumElapsedMilliseconds);
        Assert.Equal(0, await f.Db(db => db.Deployments.CountAsync()));
        Assert.Equal(0, await f.Db(db => db.OwnerNonces.CountAsync()));
        Assert.Equal(1, await f.Db(db => db.Events.CountAsync()));
        var messages = string.Join("\n", f.Logs.Messages);
        Assert.Contains(error.Diagnostic.CorrelationId, messages);
        Assert.DoesNotContain(sensitive, messages + error);
        Assert.DoesNotContain(request.Deployment.PublicKey, messages + error);
        Assert.DoesNotContain("Invalid text field", messages + error);
    }

    [Fact]
    public async Task UnauthorizedAndEarlyHttpFailuresAreSafeAndLegacyBodyUnchanged()
    {
        await using var f = new ServiceFixture { OidcAdministration = false }; f.Http = f.NewClient();
        using var unauthorized = await f.Http.PostAsync("/owner-control/v1/deployments/enroll", new StringContent("sensitive-input"));
        Assert.Equal(HttpStatusCode.Forbidden, unauthorized.StatusCode);
        var diagnostic = OwnerFailureDiagnostic.Read(unauthorized.Headers, unauthorized.StatusCode)!;
        Assert.Equal("authorization", diagnostic.Stage); Assert.Equal("not_authorized", diagnostic.Code);
        Assert.Equal("{\"code\":\"connection_not_authorized\"}", await unauthorized.Content.ReadAsStringAsync());
        using var insecure = await f.Http.PostAsync("http://connections.example.com/owner-control/v1/access", new StringContent("sensitive-input"));
        Assert.Equal(HttpStatusCode.BadRequest, insecure.StatusCode);
        Assert.Equal("transport", OwnerFailureDiagnostic.Read(insecure.Headers, insecure.StatusCode)!.Stage);
        Assert.Equal("", await insecure.Content.ReadAsStringAsync());
        Assert.NotEqual(diagnostic.CorrelationId, OwnerFailureDiagnostic.Read(insecure.Headers, insecure.StatusCode)!.CorrelationId);
        Assert.DoesNotContain("sensitive-input", string.Join("\n", f.Logs.Messages));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("v1.enrollment.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.12")]
    [InlineData("v1.enrollment.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0012")]
    [InlineData("v1.enrollment.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.3600001")]
    [InlineData("v1.enrollment.request_rejected.SecretException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.12")]
    [InlineData("v1.secret.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.12")]
    [InlineData("v1.enrollment.not_authorized.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.12")]
    [InlineData("v1.enrollment.request_rejected.ArgumentException.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.12")]
    [InlineData("untrusted-secret")]
    public async Task ClientValidatesMetadataNeverReadsErrorBodyAndNeverRetries(string? metadata)
    {
        var handler = new FailureHandler(metadata); using var http = new HttpClient(handler);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client = new OwnerAdministrationClient(http, new(Guid.NewGuid(), "https://service.example", "key", 1), key, TimeProvider.System);
        var error = await Assert.ThrowsAsync<OwnerOperationException>(() => client.Access(Guid.NewGuid()));
        Assert.Equal(1, handler.Calls); Assert.Equal(HttpStatusCode.BadRequest, error.StatusCode);
        var valid = metadata == "v1.enrollment.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.12";
        Assert.Equal(valid, error.Diagnostic is not null);
        Assert.DoesNotContain("untrusted-secret", error.ToString());
    }

    [Fact]
    public void DuplicatedOversizedOrUnauthorizedDetailedMetadataIsIgnored()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.BadRequest);
        response.Headers.TryAddWithoutValidation(OwnerFailureDiagnostic.Header, new[] { "v1.enrollment.request_rejected.ArgumentException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1", "extra" });
        Assert.Null(OwnerFailureDiagnostic.Read(response.Headers, response.StatusCode));
        response.Headers.Remove(OwnerFailureDiagnostic.Header);
        response.Headers.TryAddWithoutValidation(OwnerFailureDiagnostic.Header, new string('x', 5000));
        Assert.Null(OwnerFailureDiagnostic.Read(response.Headers, response.StatusCode));
        response.Headers.Remove(OwnerFailureDiagnostic.Header);
        response.Headers.TryAddWithoutValidation(OwnerFailureDiagnostic.Header, "v1.enrollment.not_authorized.UnauthorizedAccessException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1");
        Assert.Null(OwnerFailureDiagnostic.Read(response.Headers, HttpStatusCode.Forbidden));
        response.Headers.Remove(OwnerFailureDiagnostic.Header);
        response.Headers.TryAddWithoutValidation(OwnerFailureDiagnostic.Header, "v1.authorization.not_authorized.CryptographicException.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1");
        Assert.Null(OwnerFailureDiagnostic.Read(response.Headers, HttpStatusCode.Forbidden));
    }

    [Fact]
    public async Task CancellationDoesNotRetryOrReadAnyFailurePayload()
    {
        var handler = new FailureHandler(null, true); using var http = new HttpClient(handler);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client = new OwnerAdministrationClient(http, new(Guid.NewGuid(), "https://service.example", "key", 1), key, TimeProvider.System);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.Access(Guid.NewGuid(), cancellation.Token));
        Assert.Equal(1, handler.Calls);
    }
    private sealed class FailureHandler(string? metadata, bool stall = false) : HttpMessageHandler
    {
        public int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            if (stall) await Task.Delay(Timeout.Infinite, cancellationToken);
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new NeverReadContent() };
            if (metadata is not null) response.Headers.TryAddWithoutValidation(OwnerFailureDiagnostic.Header, metadata);
            return response;
        }
    }
    private sealed class NeverReadContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new Exception("Failure body must never be read.");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }
}
