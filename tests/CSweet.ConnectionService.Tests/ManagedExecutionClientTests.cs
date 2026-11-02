using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedExecutionClientTests
{
    [Theory]
    [InlineData("connection")]
    [InlineData("binding")]
    [InlineData("revision")]
    public async Task ClientRejectsResponsesForAnotherSignedOperation(string change)
    {
        var id = Guid.NewGuid(); var operation = Operation(); var handler = new RelayHandler(async (request, ct) =>
        {
            Assert.Equal($"/v1/connections/{id:D}/operations/read", request.RequestUri!.AbsolutePath);
            Assert.Equal(HttpMethod.Post, request.Method);
            var sent = await request.Content!.ReadFromJsonAsync<ManagedReadRequest>(ct);
            Assert.Equal(operation.CorePlanHash, sent!.CorePlanHash);
            return new(HttpStatusCode.OK) { Content = JsonContent.Create(new ManagedReadResult(change == "connection" ? Guid.NewGuid() : id,
                change == "revision" ? 0 : 1, change == "binding" ? new string('b', 64) : ManagedExecutionBinding.Hash(id, operation), JsonSerializer.SerializeToElement(new { }))) };
        });
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var http = new HttpClient(handler);
        var client = new ManagedConnectionClient(http, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReadOperation(id, operation)); Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BodyReadDeadlineAndCallerCancellationNeverRetry(bool callerCancellation)
    {
        var handler = new RelayHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StalledBody()) }));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var http = new HttpClient(handler) { Timeout = callerCancellation ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(100) };
        var client = new ManagedConnectionClient(http, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        using var cancellation = new CancellationTokenSource(); if (callerCancellation) cancellation.CancelAfter(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReadOperation(Guid.NewGuid(), Operation(), cancellation.Token));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public void DiagnosticStringsExcludeOperationInputAndResultContent()
    {
        var request = Operation() with { Input = JsonSerializer.SerializeToElement(new { title = "synthetic-private-content" }) };
        Assert.DoesNotContain("synthetic-private-content", request.ToString());
        Assert.DoesNotContain("synthetic-private-content", new ManagedReadResult(Guid.NewGuid(), 1, new string('a', 64), request.Input).ToString());
    }
    private static ManagedReadRequest Operation() => new("tenant", Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), "sample.read.v1", "resource",
        JsonSerializer.SerializeToElement(new { }), new string('a', 64), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 30);
    private sealed class RelayHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        public int Calls;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        { Calls++; var response = await send(request, ct); response.Headers.Add("X-CSweet-Connection-Protocol", ConnectionProtocol.Version); return response; }
    }
    private sealed class StalledBody : Stream
    {
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { await Task.Delay(Timeout.Infinite, ct); return 0; }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
