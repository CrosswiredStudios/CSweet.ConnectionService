using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>No provider or vault dependency. Only compatible, separately approved package authority
/// is adopted, with an atomic immutable receipt; original consent and erasure provenance remain.</summary>
public sealed class ConnectionAdoptionService(ConnectionStore db,RegistryService registry,TimeProvider clock)
{
    public async Task<ConnectionAdoptionPreview> Preview(Deployment deployment,Guid id,ConnectionAdoptionRequest request,CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));ct=deadline.Token;
        await using var transaction=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct);
        var result=await Require(deployment,id,request,ct); await transaction.CommitAsync(ct); return result;
    }
    public async Task<ConnectionAdoptionReceipt> Adopt(Deployment deployment,Guid id,ApproveConnectionAdoption approval,CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));ct=deadline.Token;
        await using var transaction=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct);
        var request=approval.Request; Validate(request); await Active(deployment,ct);
        var existing=await db.Adoptions.AsNoTracking().SingleOrDefaultAsync(x=>x.DeploymentId==deployment.Id && x.Id==request.AdoptionId,ct);
        if(existing is not null)
        { Match(existing,id,request);if(existing.ReviewHash!=approval.ReviewHash || existing.Outcome!="Adopted")throw new UnauthorizedAccessException();return await View(existing,ct); }
        var preview=await Require(deployment,id,request,ct);
        if(approval.ReviewHash!=preview.ReviewHash)throw new UnauthorizedAccessException("The adoption review changed.");
        var connection=await db.Connections.SingleAsync(x=>x.Id==id && x.DeploymentId==deployment.Id,ct);
        connection.InstallationId=request.TargetInstallationId;connection.PackageDigest=request.TargetPackageDigest;connection.Revision++;
        var row=Record(deployment,id,request,"Adopted",connection.Revision,preview.ReviewHash,preview.CompatibilityHash);
        db.Adoptions.Add(row);db.Event(deployment.Id,"connection.package-adopted",id,connection.Revision,clock.GetUtcNow(),target:row.Id.ToString("D"));
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return Receipt(row,connection);
    }
    public async Task<ConnectionAdoptionStatus> Status(Deployment deployment,Guid adoptionId,CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));ct=deadline.Token;
        await using var transaction=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct);
        await Active(deployment,ct);
        var row=await db.Adoptions.AsNoTracking().SingleOrDefaultAsync(x=>x.DeploymentId==deployment.Id && x.Id==adoptionId,ct);
        var result=new ConnectionAdoptionStatus(row is not null,row is null ? null : await View(row,ct));
        await transaction.CommitAsync(ct);return result;
    }
    public async Task<ConnectionAdoptionReceipt> Cancel(Deployment deployment,Guid id,ConnectionAdoptionRequest request,CancellationToken ct)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));ct=deadline.Token;
        await using var transaction=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct);
        Validate(request);await Active(deployment,ct);
        var existing=await db.Adoptions.AsNoTracking().SingleOrDefaultAsync(x=>x.DeploymentId==deployment.Id && x.Id==request.AdoptionId,ct);
        if(existing is not null){Match(existing,id,request);return await View(existing,ct);}
        var connection=await Source(deployment,id,request,ct);
        // This fence is useful even when profile/package/connection authority was revoked.
        // A later Adopt with this ID can never resurrect it or create another authority.
        var row=Record(deployment,id,request,"Cancelled",connection.Revision,"","");
        db.Adoptions.Add(row);db.Event(deployment.Id,"connection.package-adoption-cancelled",id,connection.Revision,clock.GetUtcNow(),target:row.Id.ToString("D"));
        await db.SaveChangesAsync(ct);await transaction.CommitAsync(ct);return Receipt(row,connection);
    }
    private async Task<ConnectionAdoptionPreview> Require(Deployment deployment,Guid id,ConnectionAdoptionRequest request,CancellationToken ct)
    {
        Validate(request);await Active(deployment,ct);var connection=await Source(deployment,id,request,ct);
        if(connection.Revision!=request.ExpectedConnectionRevision || connection.Status!="Ready" || connection.SubjectHash is null ||
            connection.InventoryVerifiedAt is not { } verified || verified>clock.GetUtcNow() ||
            connection.ProtectedCredentials.Length==0 || connection.ProtectedInventory.Length==0 ||
            connection.LeaseOwner is not null || connection.LeaseUntil is not null ||
            await db.Connections.AnyAsync(x=>x.DeploymentId==deployment.Id && x.InstallationId==request.TargetInstallationId && x.Id!=id,ct) ||
            await db.MediaTransfers.AnyAsync(x=>x.ConnectionId==id && x.State!="Cancelled" && x.State!="Expired",ct))throw new UnauthorizedAccessException();
        Guards.Digest(connection.SubjectHash);
        var (oldPackage,oldManifest,oldProfile)=await registry.Resolve(request.SourcePackageDigest,ct);
        var (newPackage,_,newProfile)=await registry.Resolve(request.TargetPackageDigest,ct);
        if(oldPackage.RepositoryUrl!=newPackage.RepositoryUrl || connection.ProfileId!=oldProfile.Id || oldProfile.Id!=newProfile.Id ||
            connection.ProfileRevision!=oldProfile.Revision || oldProfile.Revision!=newProfile.Revision ||
            registry.Availability(oldProfile).BindingHash!=request.ExpectedProfileBinding)throw new UnauthorizedAccessException();
        if(verified<=clock.GetUtcNow().AddHours(-oldManifest.Accounts!.Lifecycle.AuthorizationCheckHours))throw new UnauthorizedAccessException();
        var scopes=JsonSerializer.Deserialize<string[]>(connection.GrantedScopeSetsJson)!;
        using var before=JsonDocument.Parse(oldPackage.ManifestJson);using var after=JsonDocument.Parse(newPackage.ManifestJson);
        var compatible=CompatibleConnectionContract.Require(before.RootElement,after.RootElement,scopes);
        var requestHash=Hash(request);
        var review=Hash(new{requestHash,compatible,connection.Revision,connection.SubjectHash,connection.InventoryVerifiedAt,
            connection.ProfileId,connection.ProfileRevision,scopes= scopes.Order(StringComparer.Ordinal).ToArray(),DeploymentRevision=deployment.Revision});
        return new(requestHash,review,compatible,connection.Revision,scopes);
    }
    private async Task<ManagedConnection> Source(Deployment deployment,Guid id,ConnectionAdoptionRequest request,CancellationToken ct)
    {
        var connection=await db.Connections.SingleOrDefaultAsync(x=>x.Id==id && x.DeploymentId==deployment.Id,ct)??throw new UnauthorizedAccessException();
        if(connection.InstallationId!=request.SourceInstallationId || connection.PackageDigest!=request.SourcePackageDigest ||
            !await db.Sessions.AsNoTracking().AnyAsync(x=>x.Id==request.OriginalConsentSessionId && x.DeploymentId==deployment.Id && x.ConnectionId==id && x.Redeemed && x.ActorId==request.ActorId,ct))
            throw new UnauthorizedAccessException();
        return connection;
    }
    private async Task Active(Deployment deployment,CancellationToken ct)
    {if(!await db.Deployments.AsNoTracking().AnyAsync(x=>x.Id==deployment.Id && !x.Revoked && x.Revision==deployment.Revision &&
        x.TenantId==deployment.TenantId,ct))throw new UnauthorizedAccessException();}
    private static void Validate(ConnectionAdoptionRequest request)
    {
        if(request.OriginalConsentSessionId==Guid.Empty || request.AdoptionId==Guid.Empty || request.SourceInstallationId==Guid.Empty || request.TargetInstallationId==Guid.Empty ||
            request.SourceInstallationId==request.TargetInstallationId || request.SourcePackageDigest==request.TargetPackageDigest ||
            request.ExpectedConnectionRevision<1)throw new ArgumentException("A distinct reviewed revision is required.");
        Guards.Digest(request.SourcePackageDigest);Guards.Digest(request.TargetPackageDigest);Guards.Digest(request.ExpectedProfileBinding);Guards.Id(request.ActorId);
    }
    private ManagedConnectionAdoption Record(Deployment deployment,Guid id,ConnectionAdoptionRequest request,string outcome,long revision,string review,string compatible)
        =>new(){Id=request.AdoptionId,DeploymentId=deployment.Id,ConnectionId=id,RequestHash=Hash(request),RequestJson=JsonSerializer.Serialize(request,DeploymentProofCodec.Json),ReviewHash=review,
            CompatibilityHash=compatible,Outcome=outcome,AdoptedRevision=revision,CreatedAt=clock.GetUtcNow()};
    private static void Match(ManagedConnectionAdoption row,Guid id,ConnectionAdoptionRequest request)
    {if(row.ConnectionId!=id || row.RequestHash!=Hash(request))throw new UnauthorizedAccessException();}
    private async Task<ConnectionAdoptionReceipt> View(ManagedConnectionAdoption row,CancellationToken ct)
        =>Receipt(row,await db.Connections.AsNoTracking().SingleAsync(x=>x.Id==row.ConnectionId && x.DeploymentId==row.DeploymentId,ct));
    private static ConnectionAdoptionReceipt Receipt(ManagedConnectionAdoption row,ManagedConnection connection)
        =>new(row.Id,row.ConnectionId,row.RequestHash,row.ReviewHash,row.CompatibilityHash,row.Outcome,row.AdoptedRevision,connection.Status,
            connection.Revision,connection.InstallationId,connection.PackageDigest);
    private static string Hash<T>(T value)=>CompatibleConnectionContract.Hash(JsonSerializer.SerializeToElement(value,DeploymentProofCodec.Json));
}
