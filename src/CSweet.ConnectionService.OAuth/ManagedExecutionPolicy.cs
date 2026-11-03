using CSweet.ConnectionService.Protocol;

namespace CSweet.ConnectionService;

/// <summary>Operator-owned exact allowlist. Enrollment and consent never create an execution policy.</summary>
public sealed class ManagedExecutionPolicy
{
    public Guid DeploymentId { get; set; }
    public string TenantId { get; set; } = "";
    public string[] PackageDigests { get; set; } = [];
    public bool AllowReads { get; set; }
    public bool AllowResumableMedia { get; set; }
    public long Revision { get; set; } = 1;

    internal static void Validate(ManagedExecutionPolicy[] policies)
    {
        if (policies.Length > 1000 || policies.Select(x => x.DeploymentId).Distinct().Count() != policies.Length)
            throw new InvalidOperationException("Execution policies must identify distinct deployments.");
        foreach (var policy in policies)
        {
            if (policy.DeploymentId == Guid.Empty || policy.Revision < 1 || policy.PackageDigests.Length is < 1 or > 20 ||
                policy.PackageDigests.Distinct(StringComparer.Ordinal).Count() != policy.PackageDigests.Length)
                throw new InvalidOperationException("Execution policy requires exact deployment/package bindings.");
            Guards.Id(policy.TenantId);
            foreach (var digest in policy.PackageDigests) Guards.Digest(digest);
        }
    }

    internal static string Require(ServiceOptions options, Deployment deployment, string package, bool media = false)
    {
        Validate(options.ExecutionPolicies);
        var policy = options.ExecutionPolicies.SingleOrDefault(x => x.DeploymentId == deployment.Id &&
            x.TenantId == deployment.TenantId && x.PackageDigests.Contains(package, StringComparer.Ordinal));
        if (policy is null || (media ? !policy.AllowResumableMedia : !policy.AllowReads)) throw new UnauthorizedAccessException();
        return DeploymentProofCodec.Hash(System.Text.Json.JsonSerializer.Serialize(new { policy.DeploymentId, policy.TenantId,
            Packages = policy.PackageDigests.Order(StringComparer.Ordinal), policy.AllowReads, policy.AllowResumableMedia, policy.Revision }));
    }
}
