using System.Net;
using System.Security.Cryptography;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService.Tests;

public sealed class ProtocolClientTests
{
    [Fact]
    public async Task ClientRejectsResponsesWithoutTheNegotiatedProtocol()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var http = new HttpClient(new ResponseHandler());
        var client = new ManagedConnectionClient(http, new("https://service.example"), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.Events(0));
    }
    [Theory]
    [InlineData("http://service.example")]
    [InlineData("https://service.example/unexpected-path")]
    [InlineData("https://user:password@service.example")]
    public async Task ClientNeverSendsToAnUnsafeServiceOrigin(string origin)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var handler = new ResponseHandler(); using var http = new HttpClient(handler);
        var client = new ManagedConnectionClient(http, new(origin), Guid.NewGuid(), "key", 1, key, TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.Events(0)); Assert.Equal(0, handler.Calls);
    }
    private sealed class ResponseHandler : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") }); }
    }
}
