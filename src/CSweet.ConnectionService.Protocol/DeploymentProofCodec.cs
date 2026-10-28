using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CSweet.ConnectionService.Protocol;

public static class DeploymentProofCodec
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { PropertyNameCaseInsensitive = false };
    public static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] Decode(string value)
    {
        if (value.Length > 16384 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) throw new FormatException("Invalid encoding.");
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight((padded.Length + 3) / 4 * 4, '='));
    }
    public static string Hash(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));
    public static string Hash(string value) => Hash(Encoding.UTF8.GetBytes(value));
    public static string Random() => Encode(RandomNumberGenerator.GetBytes(32));
    public static string Challenge(string verifier) => Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
    public static bool Equal(string left, string right) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
    public static string Sign(DeploymentProof proof, ECDsa key)
    {
        var payload = Encode(JsonSerializer.SerializeToUtf8Bytes(proof, Json));
        return payload + "." + Encode(key.SignData(Encoding.ASCII.GetBytes("csweet.connection-proof.v1." + payload), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    public static DeploymentProof Verify(string value, ECDsa key)
    {
        if (value.Length > 8192) throw new CryptographicException("Invalid proof.");
        var segments = value.Split('.');
        if (segments.Length != 2 || !key.VerifyData(Encoding.ASCII.GetBytes("csweet.connection-proof.v1." + segments[0]), Decode(segments[1]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new CryptographicException("Invalid proof.");
        using var doc = JsonDocument.Parse(Decode(segments[0]));
        if (doc.RootElement.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != doc.RootElement.EnumerateObject().Count()) throw new CryptographicException("Ambiguous proof.");
        return doc.RootElement.Deserialize<DeploymentProof>(Json) ?? throw new CryptographicException("Invalid proof.");
    }
    public static ECDsa PublicKey(string spki)
    {
        var key = ECDsa.Create();
        try
        {
            var bytes = Decode(spki); key.ImportSubjectPublicKeyInfo(bytes, out var read);
            if (read != bytes.Length || key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new CryptographicException("P-256 public key required.");
            return key;
        }
        catch { key.Dispose(); throw; }
    }
}
