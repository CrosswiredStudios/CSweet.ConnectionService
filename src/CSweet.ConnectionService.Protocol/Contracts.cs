using System.Text.Json.Serialization;
using System.Text.Json;

namespace CSweet.ConnectionService.Protocol;

public static class ConnectionProtocol
{
    public const string Version = "1.0";
    public const string ProofHeader = "X-CSweet-Deployment-Proof";
    public const int MaximumBodyBytes = 1024 * 1024;
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record EnrollDeployment(string Name, string PublicKey, string KeyId, IReadOnlyList<string> ReturnUris);
public sealed record DeploymentRegistration(Guid DeploymentId, string TenantId, long Revision);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record RotateDeploymentKey(string PublicKey, string KeyId, long ExpectedRevision);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ConfigureProvider(string Id, string ClientId, string AuthorizationEndpoint, string TokenEndpoint, string RevocationEndpoint, string ClientSecret)
{
    public string? RevocationGroup { get; init; }
    public override string ToString() => $"Provider configuration {Id} [credentials redacted]";
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ApprovePackage(string PackageDigest, string ManifestSha256, string ManifestJson, string ProfileId, long ProfileRevision, string RepositoryUrl, string SourceCommit);
public sealed record ProfileAvailability(string ProfileId, long PublicRevision, string BindingHash, string CallbackUri);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record BeginConnection(Guid LocalAttemptId, Guid InstallationId, string ActorId, string PackageDigest, string DeclarationId,
    IReadOnlyList<string> ScopeSetIds, string PolicyVersion, bool AcceptPolicies, string ReturnUri, string ReturnChallenge);
public sealed record ConnectionAttempt(Guid SessionId, string Status, string? LaunchUrl, DateTimeOffset ExpiresAt);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record RedeemConnection(string Handoff, string ReturnVerifier, Guid LocalAttemptId, string ActorId, string PackageDigest)
{
    public override string ToString() => "Managed connection handoff [proof redacted]";
}
public sealed record ConnectionReceipt(Guid SessionId, Guid? ConnectionId, string Status, string? FailureCode, IReadOnlyList<string> GrantedScopeSets);
public sealed record RecoverConnection(Guid LocalAttemptId, string ActorId, string PackageDigest, string ReturnVerifier)
{ public override string ToString() => "Managed connection recovery [proof redacted]"; }
public sealed record ConnectionSnapshot(Guid ConnectionId, string Status, long Revision, IReadOnlyList<string> GrantedScopeSets);
public sealed record ManagedResource(string Id, string Name, string? Handle);
public sealed record ConnectionInventory(Guid ConnectionId, string Status, long Revision, string? Subject, string? Name,
    string? IdentityAuthority, IReadOnlyList<ManagedResource> Resources, IReadOnlyList<string> GrantedScopeSets);
public sealed record ServiceEvent(long Sequence, Guid Id, string Kind, Guid? ConnectionId, long Revision, DateTimeOffset CreatedAt, Guid? SessionId = null);
public sealed record ServiceFailure(string Code);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record DeploymentProof(Guid DeploymentId, string KeyId, string Audience, string Method, string PathAndQuery,
    string BodySha256, long IssuedAt, long ExpiresAt, string Nonce, long DeploymentRevision);
