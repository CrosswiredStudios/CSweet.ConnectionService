using CSweet.ConnectionService.Protocol;
using System.Security.Cryptography;

using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var proof = new DeploymentProof(Guid.NewGuid(), "key-1", "https://service.example", "GET", "/v1/events?after=0", DeploymentProofCodec.Hash(""), 100, 130, DeploymentProofCodec.Random(), 1);
if (DeploymentProofCodec.Verify(DeploymentProofCodec.Sign(proof, key), key) != proof) throw new InvalidOperationException("Packaged protocol failed conformance.");
Console.WriteLine($"NuGet-only connection protocol consumer: {ConnectionProtocol.Version}.");
