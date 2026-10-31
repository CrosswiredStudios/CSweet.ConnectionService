using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CSweet.ConnectionService.Protocol;

public static class OwnerProtocol
{
    public const string ProofHeader = "X-CSweet-Owner-Proof";
    public const string AudienceSuffix = "/owner-control/v1";
    public const string Import = "credentials.import", Approve = "packages.approve", Enroll = "deployments.enroll", Revoke = "deployments.revoke";
    public static readonly string[] Capabilities = [Import, Approve, Enroll, Revoke];
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OwnerRequest<T>(Guid ActorId, long GrantRevision, T Payload);
public sealed record OwnerRegistration(Guid BindingId, string ServiceOrigin, string KeyId, long Revision);
public sealed record OwnerAccess(OwnerRegistration Registration, Guid ActorId, long GrantRevision, string TenantScope, string[] Capabilities);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OwnerCredentialImport(string Format, string ProfileId, JsonElement Document)
{ public override string ToString() => "Owner credential import [redacted]"; }
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OwnerEnrollment(string TenantId, EnrollDeployment Deployment);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record OwnerRevocation(string TenantId, Guid DeploymentId);
public sealed record OwnerAccepted(bool Accepted);
public sealed record ConnectionServiceCapabilities(string Origin, string Protocol, bool OAuthAccountSetup, bool MobilePairing, bool GeneralProviderActions);

/// <summary>Separate control-plane key and service-owned actor grants. This is backend attestation, not independent human approval evidence.</summary>
public sealed class OwnerAdministrationClient(HttpClient http, OwnerRegistration registration, ECDsa key, TimeProvider clock)
{
    public Task<OwnerAccess> Access(Guid actor, CancellationToken ct = default) => Send<OwnerAccess>("access", new OwnerRequest<object>(actor, 0, new { }), ct);
    public Task<ProfileAvailability> Import(Guid actor, long grantRevision, OwnerCredentialImport request, CancellationToken ct = default) => Send<ProfileAvailability>("credentials/import", new OwnerRequest<OwnerCredentialImport>(actor, grantRevision, request), ct);
    public Task<OwnerAccepted> Approve(Guid actor, long grantRevision, ApprovePackage request, CancellationToken ct = default) => Send<OwnerAccepted>("packages/approve", new OwnerRequest<ApprovePackage>(actor, grantRevision, request), ct);
    public Task<DeploymentRegistration> Enroll(Guid actor, long grantRevision, OwnerEnrollment request, CancellationToken ct = default) => Send<DeploymentRegistration>("deployments/enroll", new OwnerRequest<OwnerEnrollment>(actor, grantRevision, request), ct);
    public Task<OwnerAccepted> Revoke(Guid actor, long grantRevision, OwnerRevocation request, CancellationToken ct = default) => Send<OwnerAccepted>("deployments/revoke", new OwnerRequest<OwnerRevocation>(actor, grantRevision, request), ct);
    private async Task<T> Send<T>(string action, object body, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(http.Timeout == Timeout.InfiniteTimeSpan ? TimeSpan.FromSeconds(30) : http.Timeout);
        ct = deadline.Token;
        var origin = new Uri(registration.ServiceOrigin);
        if (origin.Scheme != "https" || origin.AbsolutePath != "/" || origin.UserInfo != "" || origin.Query != "" || origin.Fragment != "") throw new InvalidOperationException("Exact HTTPS origin required.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(body, DeploymentProofCodec.Json);
        if (bytes.Length > ConnectionProtocol.MaximumBodyBytes) throw new ArgumentException("Request exceeds limit.");
        var path = "/owner-control/v1/" + action; var now = clock.GetUtcNow().ToUnixTimeSeconds();
        var proof = new DeploymentProof(registration.BindingId, registration.KeyId, registration.ServiceOrigin + OwnerProtocol.AudienceSuffix,
            "POST", path, DeploymentProofCodec.Hash(bytes), now, now + 30, DeploymentProofCodec.Random(), registration.Revision);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, path));
        request.Headers.Add(OwnerProtocol.ProofHeader, DeploymentProofCodec.Sign(proof, key));
        request.Content = new ByteArrayContent(bytes); request.Content.Headers.ContentType = new("application/json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) throw new OwnerOperationException(response.StatusCode, OwnerFailureDiagnostic.Read(response.Headers, response.StatusCode));
        await using var input = await response.Content.ReadAsStreamAsync(ct); using var output = new MemoryStream(); var buffer = new byte[8192];
        int count; while ((count = await input.ReadAsync(buffer, ct)) != 0) { if (output.Length + count > ConnectionProtocol.MaximumBodyBytes) throw new InvalidOperationException("Result exceeds limit."); output.Write(buffer, 0, count); }
        return JsonSerializer.Deserialize<T>(output.ToArray(), DeploymentProofCodec.Json) ?? throw new InvalidOperationException("Empty result.");
    }
}
