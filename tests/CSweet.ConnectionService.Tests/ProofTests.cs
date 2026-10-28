using System.Net;
using System.Security.Cryptography;
using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService.Tests;

public sealed class ProofTests
{
    [Fact]
    public void SignatureBindsEveryRequestField()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = new DeploymentProof(Guid.NewGuid(), "key-1", "https://service.example", "POST", "/v1/sessions", DeploymentProofCodec.Hash("{}"), 100, 130, DeploymentProofCodec.Random(), 1);
        var signed = DeploymentProofCodec.Sign(p, key);
        using var publicKey = DeploymentProofCodec.PublicKey(DeploymentProofCodec.Encode(key.ExportSubjectPublicKeyInfo()));
        Assert.Equal(p, DeploymentProofCodec.Verify(signed, publicKey));
        var changed = signed[..^3] + (signed[^3] == 'a' ? 'b' : 'a') + signed[^2..];
        Assert.ThrowsAny<CryptographicException>(() => DeploymentProofCodec.Verify(changed, publicKey));
    }
    [Fact]
    public void AnotherDeploymentKeyCannotVerifyProof()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = new DeploymentProof(Guid.NewGuid(), "key", "https://service.example", "GET", "/v1/events", "hash", 100, 130, DeploymentProofCodec.Random(), 1);
        Assert.Throws<CryptographicException>(() => DeploymentProofCodec.Verify(DeploymentProofCodec.Sign(p, key), other));
    }
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.4")]
    [InlineData("169.254.169.254")]
    [InlineData("192.168.1.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    [InlineData("2002:7f00:1::")]
    public void ProviderTransportRejectsPrivateAndTransitionAddresses(string address) => Assert.True(PinnedProviderTransport.IsForbidden(IPAddress.Parse(address)));
    [Theory]
    [InlineData("http://example.com/callback")]
    [InlineData("https://127.0.0.1/callback")]
    [InlineData("https://user:password@example.com/callback")]
    [InlineData("https://example.com/callback?redirect=anything")]
    [InlineData("https://example.com/callback#fragment")]
    public void ReturnEnrollmentRejectsUnsafeTargets(string target) => Assert.Throws<ArgumentException>(() => Guards.Https(target));
    [Fact]
    public void ProductionCannotUseDevelopmentStorageDefaults() => Assert.ThrowsAny<Exception>(() => new ServiceOptions().Validate(false));
}
