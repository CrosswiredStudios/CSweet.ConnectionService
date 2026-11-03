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

var relayConnection = Guid.NewGuid();
var operation = new ManagedReadRequest("tenant", Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), "sample.read.v1", "resource",
    System.Text.Json.JsonSerializer.SerializeToElement(new { }), new string('b', 64), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30);
using var relayHttp = new HttpClient(new RelayFixture(key, relayConnection));
var relay = new ManagedConnectionClient(relayHttp, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
var relayResult = await relay.ReadOperation(relayConnection, operation);
if (relayResult.OperationHash != ManagedExecutionBinding.Hash(relayConnection, operation)) throw new InvalidOperationException("Packaged relay binding mismatch.");
Console.WriteLine("NuGet-only signed read relay and bound result passed.");
var asset = Guid.NewGuid();
var mediaPlan = new ManagedMediaRequest(operation, "synthetic-once", asset, new string('c', 64), 17, "video/mp4", "synthetic-approval", DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds());
using var mediaHttp = new HttpClient(new MediaFixture(key, relayConnection));
var mediaClient = new ManagedConnectionClient(mediaHttp, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
var transfer = await mediaClient.BeginMedia(relayConnection, mediaPlan);
var complete = await mediaClient.MediaChunk(transfer.TransferId, transfer.BindingHash, 0, new byte[17]);
if (complete.State != "Completed" || complete.CommittedBytes != 17) throw new InvalidOperationException("Packaged media contract mismatch.");
Console.WriteLine("NuGet-only signed binary media chunk and durable binding passed.");

sealed class MediaFixture(ECDsa key, Guid connection) : HttpMessageHandler
{
    private readonly Guid transfer = Guid.NewGuid(); private string binding = "";
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var proof = DeploymentProofCodec.Verify(request.Headers.GetValues(ConnectionProtocol.ProofHeader).Single(), key);
        var body = await request.Content!.ReadAsByteArrayAsync(ct);
        if (proof.BodySha256 != DeploymentProofCodec.Hash(body) || proof.PathAndQuery != request.RequestUri!.PathAndQuery || proof.Method != "POST") throw new InvalidOperationException("Invalid media proof.");
        ManagedMediaResult result;
        if (request.RequestUri.AbsolutePath.EndsWith("/media", StringComparison.Ordinal))
        { var plan = System.Text.Json.JsonSerializer.Deserialize<ManagedMediaRequest>(body, DeploymentProofCodec.Json)!; binding = plan.BindingHash(connection); result = new(transfer, binding, "Ready", 201, 0, 1); }
        else
        {
            if (request.Content.Headers.ContentType?.MediaType != "application/octet-stream" || body.Length != 17 ||
                request.RequestUri.AbsolutePath != $"/v1/media/{transfer:D}/chunks/0/{binding}") throw new InvalidOperationException("Invalid binary media range.");
            result = new(transfer, binding, "Completed", 200, 17, 2, System.Text.Json.JsonSerializer.SerializeToElement(new { }));
        }
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = System.Net.Http.Json.JsonContent.Create(result) };
        response.Headers.Add("X-CSweet-Connection-Protocol", ConnectionProtocol.Version); return response;
    }
}

sealed class RelayFixture(ECDsa key, Guid connection) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var proof = DeploymentProofCodec.Verify(request.Headers.GetValues(ConnectionProtocol.ProofHeader).Single(), key);
        var body = await request.Content!.ReadAsByteArrayAsync(ct);
        var operation = System.Text.Json.JsonSerializer.Deserialize<ManagedReadRequest>(body, DeploymentProofCodec.Json)!;
        if (proof.BodySha256 != DeploymentProofCodec.Hash(body) || proof.Method != "POST" ||
            proof.PathAndQuery != $"/v1/connections/{connection:D}/operations/read") throw new InvalidOperationException("Invalid packaged relay proof.");
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = System.Net.Http.Json.JsonContent.Create(
            new ManagedReadResult(connection, 1, ManagedExecutionBinding.Hash(connection, operation), System.Text.Json.JsonSerializer.SerializeToElement(new { }))) };
        response.Headers.Add("X-CSweet-Connection-Protocol", ConnectionProtocol.Version); return response;
    }
}

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
