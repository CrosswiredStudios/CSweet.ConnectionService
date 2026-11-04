using System.Text.Json.Serialization;

namespace CSweet.ConnectionService.Protocol;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ConnectionAdoptionRequest(Guid AdoptionId, Guid SourceInstallationId, Guid TargetInstallationId,
    string SourcePackageDigest, string TargetPackageDigest, long ExpectedConnectionRevision, string ExpectedProfileBinding, string ActorId, Guid OriginalConsentSessionId);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ApproveConnectionAdoption(ConnectionAdoptionRequest Request,string ReviewHash);
public sealed record ConnectionAdoptionPreview(string RequestHash,string ReviewHash,string CompatibilityHash,
    long ConnectionRevision,IReadOnlyList<string> GrantedScopeSets);
public sealed record ConnectionAdoptionReceipt(Guid AdoptionId,Guid ConnectionId,string RequestHash,string ReviewHash,
    string CompatibilityHash,string Outcome,long AdoptedRevision,string CurrentStatus,long CurrentRevision,
    Guid CurrentInstallationId,string CurrentPackageDigest);
public sealed record ConnectionAdoptionStatus(bool Found,ConnectionAdoptionReceipt? Receipt);

public sealed partial class ManagedConnectionClient
{
    public Task<ConnectionAdoptionPreview> PreviewAdoption(Guid connection,ConnectionAdoptionRequest request,CancellationToken ct=default)
        =>Send<ConnectionAdoptionPreview>(HttpMethod.Post,$"/v1/connections/{connection:D}/adoptions/preview",request,ct);
    public Task<ConnectionAdoptionReceipt> Adopt(Guid connection,ApproveConnectionAdoption request,CancellationToken ct=default)
        =>Send<ConnectionAdoptionReceipt>(HttpMethod.Post,$"/v1/connections/{connection:D}/adoptions",request,ct);
    public Task<ConnectionAdoptionStatus> Adoption(Guid id,CancellationToken ct=default)
        =>Send<ConnectionAdoptionStatus>(HttpMethod.Get,$"/v1/adoptions/{id:D}",null,ct);
    public Task<ConnectionAdoptionReceipt> CancelAdoption(Guid connection,ConnectionAdoptionRequest request,CancellationToken ct=default)
        =>Send<ConnectionAdoptionReceipt>(HttpMethod.Post,$"/v1/connections/{connection:D}/adoptions/cancel",request,ct);
}
