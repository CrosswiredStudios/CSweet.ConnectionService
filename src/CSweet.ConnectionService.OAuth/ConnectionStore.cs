using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed class ConnectionStore(DbContextOptions<ConnectionStore> options) : DbContext(options)
{
    public DbSet<OwnerBinding> OwnerBindings => Set<OwnerBinding>();
    public DbSet<OwnerGrant> OwnerGrants => Set<OwnerGrant>();
    public DbSet<OwnerNonce> OwnerNonces => Set<OwnerNonce>();
    public DbSet<Deployment> Deployments => Set<Deployment>(); public DbSet<ProviderProfile> Profiles => Set<ProviderProfile>();
    public DbSet<PackageApproval> Packages => Set<PackageApproval>(); public DbSet<ConsentSession> Sessions => Set<ConsentSession>();
    public DbSet<ManagedConnection> Connections => Set<ManagedConnection>(); public DbSet<ProofNonce> Nonces => Set<ProofNonce>();
    public DbSet<ConnectionEvent> Events => Set<ConnectionEvent>();
    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<OwnerBinding>().HasKey(x => x.Id); model.Entity<OwnerBinding>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<OwnerGrant>().HasKey(x => new { x.BindingId, x.ActorId }); model.Entity<OwnerGrant>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<OwnerNonce>().HasKey(x => new { x.BindingId, x.NonceHash });
        model.Entity<Deployment>().HasKey(x => x.Id); model.Entity<Deployment>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<ProviderProfile>().HasKey(x => x.Id); model.Entity<ProviderProfile>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<ProviderProfile>().Property(x => x.SecretVersion).IsConcurrencyToken();
        model.Entity<PackageApproval>().HasKey(x => x.Digest);
        model.Entity<PackageApproval>().Property(x => x.Revoked).IsConcurrencyToken();
        model.Entity<ConsentSession>().HasKey(x => x.Id); model.Entity<ConsentSession>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<ConsentSession>().HasIndex(x => new { x.DeploymentId, x.LocalAttemptId }).IsUnique();
        model.Entity<ConsentSession>().HasIndex(x => x.LaunchHash).IsUnique(); model.Entity<ConsentSession>().HasIndex(x => x.HandoffHash);
        model.Entity<ManagedConnection>().HasKey(x => x.Id); model.Entity<ManagedConnection>().Property(x => x.Revision).IsConcurrencyToken();
        model.Entity<ProofNonce>().HasKey(x => new { x.DeploymentId, x.NonceHash });
        model.Entity<ConnectionEvent>().HasKey(x => x.Sequence); model.Entity<ConnectionEvent>().Property(x => x.Sequence).ValueGeneratedOnAdd();
        model.Entity<ConnectionEvent>().HasIndex(x => new { x.DeploymentId, x.Sequence });
    }
    public void Event(Guid deploymentId, string kind, Guid? connectionId, long revision, DateTimeOffset now, Guid? sessionId = null, string? operatorSubject = null, string? target = null) => Events.Add(new() { Id = Guid.NewGuid(), DeploymentId = deploymentId, Kind = kind, ConnectionId = connectionId, Revision = revision, CreatedAt = now, SessionId = sessionId, OperatorSubject = operatorSubject, Target = target });
}
public sealed class Deployment
{
    public Guid Id { get; set; }
    public string TenantId { get; set; } = ""; public string Name { get; set; } = "";
    public string PublicKey { get; set; } = ""; public string KeyId { get; set; } = ""; public string ReturnUrisJson { get; set; } = "[]";
    public long Revision { get; set; } = 1; public bool Revoked { get; set; }
}
public sealed class ProviderProfile
{
    public string Id { get; set; } = ""; public string ClientId { get; set; } = ""; public string AuthorizationEndpoint { get; set; } = "";
    public string TokenEndpoint { get; set; } = ""; public string RevocationEndpoint { get; set; } = ""; public string ProtectedSecret { get; set; } = "";
    public long Revision { get; set; } = 1; public long SecretVersion { get; set; } = 1; public bool Enabled { get; set; } = true;
    public string? RevocationGroup { get; set; }
}
public sealed class PackageApproval
{
    public string Digest { get; set; } = ""; public string ManifestSha256 { get; set; } = ""; public string ManifestJson { get; set; } = "";
    public string ProfileId { get; set; } = ""; public long ProfileRevision { get; set; }
    public bool Revoked { get; set; }
    public string RepositoryUrl { get; set; } = ""; public string SourceCommit { get; set; } = "";
}
public sealed class ConsentSession
{
    public Guid Id { get; set; }
    public Guid DeploymentId { get; set; }
    public Guid InstallationId { get; set; }
    public Guid LocalAttemptId { get; set; }
    public string ActorId { get; set; } = ""; public string PackageDigest { get; set; } = ""; public string DeclarationId { get; set; } = "";
    public string ScopeSetIdsJson { get; set; } = "[]"; public string RequestedScopesJson { get; set; } = "[]"; public string PolicyVersion { get; set; } = "";
    public string ReturnUri { get; set; } = ""; public string ReturnChallenge { get; set; } = ""; public string RequestHash { get; set; } = "";
    public string LaunchHash { get; set; } = ""; public string ProtectedLaunch { get; set; } = ""; public string StateHash { get; set; } = "";
    public string BrowserHash { get; set; } = ""; public string ProtectedVerifier { get; set; } = "";
    public string? HandoffHash { get; set; }
    public string? ProtectedHandoff { get; set; }
    public DateTimeOffset? HandoffExpiresAt { get; set; }
    public bool Redeemed { get; set; }
    public string Status { get; set; } = "Created"; public string? FailureCode { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public Guid? ConnectionId { get; set; }
    public long Revision { get; set; } = 1;
}
public sealed class ManagedConnection
{
    public Guid Id { get; set; }
    public Guid DeploymentId { get; set; }
    public Guid InstallationId { get; set; }
    public string PackageDigest { get; set; } = ""; public string ProfileId { get; set; } = ""; public long ProfileRevision { get; set; }
    public string ProtectedCredentials { get; set; } = ""; public string GrantedScopeSetsJson { get; set; } = "[]";
    public string Status { get; set; } = "Connected"; public long Revision { get; set; } = 1;
    public string ProtectedInventory { get; set; } = "";
    public string? SubjectHash { get; set; }
    public DateTimeOffset? InventoryVerifiedAt { get; set; }
    public Guid? LeaseOwner { get; set; }
    public DateTimeOffset? LeaseUntil { get; set; }
    public DateTimeOffset? RevocationRequestedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? FailureCode { get; set; }
    public int RevocationAttempts { get; set; }
    public long NextRevocationAttempt { get; set; }
}
public sealed class ProofNonce { public Guid DeploymentId { get; set; } public string NonceHash { get; set; } = ""; public long ExpiresAt { get; set; } }
public sealed class ConnectionEvent
{
    public long Sequence { get; set; }
    public Guid Id { get; set; }
    public Guid DeploymentId { get; set; }
    public Guid? ConnectionId { get; set; }
    public string Kind { get; set; } = ""; public long Revision { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? SessionId { get; set; }
    public string? OperatorSubject { get; set; }
    public string? Target { get; set; }
}
