using CSweet.ConnectionService.Protocol;
using System.Security.Cryptography;

using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var proof = new DeploymentProof(Guid.NewGuid(), "key-1", "https://service.example", "GET", "/v1/events?after=0", DeploymentProofCodec.Hash(""), 100, 130, DeploymentProofCodec.Random(), 1);
if (DeploymentProofCodec.Verify(DeploymentProofCodec.Sign(proof, key), key) != proof) throw new InvalidOperationException("Packaged protocol failed conformance.");
Console.WriteLine($"NuGet-only connection protocol consumer: {ConnectionProtocol.Version}.");
var registration = new OwnerRegistration(Guid.NewGuid(), "https://service.example", "owner", 1);
var actor = Guid.NewGuid();
using var http = new HttpClient(new OwnerFixture(key, registration, actor));
var owner = new OwnerAdministrationClient(http, registration, key, TimeProvider.System);
var access = await owner.Access(actor);
if (access.ActorId != actor || access.GrantRevision != 3) throw new InvalidOperationException("Packaged owner contract mismatch.");
using var stalled = new HttpClient(new StalledFixture()) { Timeout = TimeSpan.FromMilliseconds(100) };
try { await new OwnerAdministrationClient(stalled, registration, key, TimeProvider.System).Access(actor); throw new InvalidOperationException("Owner body deadline was not enforced."); }
catch (OperationCanceledException) { }
Console.WriteLine("NuGet-only owner contracts, signed request and response-body deadline passed.");
using var diagnosticResponse = new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
diagnosticResponse.Headers.Add(OwnerFailureDiagnostic.Header, new OwnerFailureDiagnostic("name", "request_rejected", "ArgumentException", new string('a', 32), 12).Encode(diagnosticResponse.StatusCode));
if (OwnerFailureDiagnostic.Read(diagnosticResponse.Headers, diagnosticResponse.StatusCode)?.Stage != "name") throw new InvalidOperationException("Packaged diagnostic contract mismatch.");
Console.WriteLine("NuGet-only owner diagnostic contract passed.");

sealed class OwnerFixture(ECDsa key, OwnerRegistration registration, Guid actor) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var proof = DeploymentProofCodec.Verify(request.Headers.GetValues(OwnerProtocol.ProofHeader).Single(), key);
        var body = await request.Content!.ReadAsByteArrayAsync(ct);
        var envelope = System.Text.Json.JsonSerializer.Deserialize<OwnerRequest<System.Text.Json.JsonElement>>(body, DeploymentProofCodec.Json)!;
        if (proof.DeploymentId != registration.BindingId || proof.Audience != registration.ServiceOrigin + OwnerProtocol.AudienceSuffix || proof.BodySha256 != DeploymentProofCodec.Hash(body) || envelope.ActorId != actor || request.RequestUri!.AbsolutePath != "/owner-control/v1/access") throw new InvalidOperationException("Invalid packaged owner proof.");
        return new(System.Net.HttpStatusCode.OK) { Content = System.Net.Http.Json.JsonContent.Create(new OwnerAccess(registration, actor, 3, "tenant", [OwnerProtocol.Enroll])) };
    }
}
sealed class StalledFixture : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StreamContent(new StalledStream()) });
}
sealed class StalledStream : Stream
{
    public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { await Task.Delay(Timeout.Infinite, ct); return 0; }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
