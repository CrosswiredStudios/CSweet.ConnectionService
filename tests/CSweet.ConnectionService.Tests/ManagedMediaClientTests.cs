using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService.Tests;

public sealed class ManagedMediaClientTests
{
    [Theory]
    [InlineData("transfer")]
    [InlineData("binding")]
    [InlineData("range")]
    [InlineData("state")]
    [InlineData("status")]
    [InlineData("completion")]
    [InlineData("retry")]
    public async Task MalformedReceiptsAreWithheldWithoutAutomaticRetry(string fault)
    {
        var transfer = Guid.NewGuid(); var binding = new string('a', 64);
        var result = new ManagedMediaResult(fault == "transfer" ? Guid.NewGuid() : transfer, fault == "binding" ? new string('b', 64) : binding,
            fault == "state" ? "untrusted-state" : fault == "completion" ? "Completed" : "Ready", fault == "status" ? 999 : 308,
            fault == "range" ? -1 : 0, 1, RetryAt: fault == "retry" ? long.MaxValue : null);
        var handler = new Response(result); using var http = new HttpClient(handler); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client = new ManagedConnectionClient(http, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ProbeMedia(transfer, binding)); Assert.Equal(1, handler.Calls);
    }
    [Fact]
    public async Task InvalidChunkIsRejectedBeforeAnyHttpRequest()
    {
        var handler = new Response(new(Guid.NewGuid(), new string('a', 64), "Ready", 308, 0, 1));
        using var http = new HttpClient(handler); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client = new ManagedConnectionClient(http, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        await Assert.ThrowsAsync<ArgumentException>(() => client.MediaChunk(Guid.NewGuid(), new string('A', 64), 0, new byte[17]));
        await Assert.ThrowsAsync<ArgumentException>(() => client.MediaChunk(Guid.NewGuid(), new string('a', 64), 0, new byte[ManagedExecutionProtocol.MaximumChunkBytes + 1]));
        Assert.Equal(0, handler.Calls);
    }
    private sealed class Response(ManagedMediaResult result) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++; var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(result) };
            response.Headers.Add("X-CSweet-Connection-Protocol", ConnectionProtocol.Version); return Task.FromResult(response);
        }
    }
}
