using System.Security.Cryptography;
using System.Text.Json;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

public sealed record ProviderNavigation(Guid SessionId, string BrowserBinding, string Url);
public sealed record CallbackReturn(Guid SessionId, string Url);
internal sealed record OAuthState(Guid SessionId, string ProfileId, long ExpiresAt, string Nonce);
internal sealed record StoredCredentials(string AccessToken, string? RefreshToken, DateTimeOffset ExpiresAt)
{ public override string ToString() => "[credentials redacted]"; }

public sealed class ConsentService(ConnectionStore db, RegistryService registry, CredentialVault vault, IProviderOAuthTransport provider, ServiceOptions options, TimeProvider clock,
    OAuthScopeConventions scopeConventions)
{
    public async Task<ConnectionAttempt> Begin(Deployment deployment, BeginConnection request, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        if (request.LocalAttemptId == Guid.Empty || request.InstallationId == Guid.Empty) throw new ArgumentException("Attempt and installation are required.");
        Guards.Text(request.ActorId, 200); Guards.Text(request.ReturnUri, 2048);
        options.ValidateReturn(request.ReturnUri);
        if (request.ReturnChallenge.Length != 43 || DeploymentProofCodec.Decode(request.ReturnChallenge).Length != 32 ||
            !JsonSerializer.Deserialize<string[]>(deployment.ReturnUrisJson)!.Contains(request.ReturnUri, StringComparer.Ordinal)) throw new UnauthorizedAccessException();
        var (_, manifest, _) = await registry.Resolve(request.PackageDigest, ct); var declaration = manifest.Connections.Single();
        if (request.DeclarationId != declaration.Id || !request.AcceptPolicies || request.PolicyVersion != manifest.Accounts!.PolicyVersion) throw new UnauthorizedAccessException();
        var selectable = manifest.Accounts.Permissions.SelectMany(x => x.ScopeSets).Concat(declaration.ScopeSets.Where(x => x.Required).Select(x => x.Id)).ToHashSet(StringComparer.Ordinal);
        if (request.ScopeSetIds.Count > 32 || request.ScopeSetIds.Distinct(StringComparer.Ordinal).Count() != request.ScopeSetIds.Count || request.ScopeSetIds.Any(x => !selectable.Contains(x))) throw new ArgumentException("Only reviewed permission sets are available.");
        var selected = declaration.ScopeSets.Where(x => x.Required || request.ScopeSetIds.Contains(x.Id, StringComparer.Ordinal)).ToArray();
        var requestHash = DeploymentProofCodec.Hash(JsonSerializer.Serialize(request, DeploymentProofCodec.Json));
        var session = await db.Sessions.SingleOrDefaultAsync(x => x.DeploymentId == deployment.Id && x.LocalAttemptId == request.LocalAttemptId, ct);
        if (session is not null)
        {
            if (session.RequestHash != requestHash) throw new InvalidOperationException("This attempt already binds different setup choices.");
            return View(session);
        }
        var launch = DeploymentProofCodec.Random();
        session = new()
        {
            Id = Guid.NewGuid(),
            DeploymentId = deployment.Id,
            InstallationId = request.InstallationId,
            LocalAttemptId = request.LocalAttemptId,
            ActorId = request.ActorId,
            PackageDigest = request.PackageDigest,
            DeclarationId = request.DeclarationId,
            ScopeSetIdsJson = JsonSerializer.Serialize(selected.Select(x => x.Id)),
            RequestedScopesJson = JsonSerializer.Serialize(selected.SelectMany(x => x.Scopes).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)),
            PolicyVersion = request.PolicyVersion,
            ReturnUri = request.ReturnUri,
            ReturnChallenge = request.ReturnChallenge,
            RequestHash = requestHash,
            LaunchHash = DeploymentProofCodec.Hash(launch),
            ExpiresAt = clock.GetUtcNow().AddMinutes(10)
        };
        session.ProtectedLaunch = vault.Seal("launch:" + session.Id, launch);
        db.Sessions.Add(session); db.Event(deployment.Id, "consent.started", null, session.Revision, clock.GetUtcNow(), session.Id); await db.SaveChangesAsync(ct);
        return View(session);
    }
    public async Task<ProviderNavigation> Launch(string handle, CancellationToken ct)
    {
        if (handle.Length != 43) throw new UnauthorizedAccessException();
        var hash = DeploymentProofCodec.Hash(handle);
        var session = await db.Sessions.SingleOrDefaultAsync(x => x.LaunchHash == hash && x.Status == "Created", ct) ?? throw new UnauthorizedAccessException();
        await Active(session.DeploymentId, null, ct);
        if (session.ExpiresAt <= clock.GetUtcNow()) throw new UnauthorizedAccessException();
        options.ValidateReturn(session.ReturnUri);
        var (_, manifest, profile) = await registry.Resolve(session.PackageDigest, ct);
        var browser = DeploymentProofCodec.Random(); var verifier = DeploymentProofCodec.Random();
        var state = vault.Seal("oauth-state", JsonSerializer.Serialize(new OAuthState(session.Id, profile.Id, session.ExpiresAt.ToUnixTimeSeconds(), DeploymentProofCodec.Random())));
        session.BrowserHash = DeploymentProofCodec.Hash(browser); session.StateHash = DeploymentProofCodec.Hash(state);
        session.ProtectedVerifier = vault.Seal("pkce:" + session.Id, verifier); session.ProtectedLaunch = ""; session.Status = "AwaitingConsent"; session.Revision++;
        db.Event(session.DeploymentId, "consent.awaiting-provider", null, session.Revision, clock.GetUtcNow(), session.Id);
        await db.SaveChangesAsync(ct);
        var parameters = new Dictionary<string, string>(manifest.Connections.Single().Provider!.AuthorizationParameters, StringComparer.Ordinal)
        {
            ["client_id"] = profile.ClientId,
            ["redirect_uri"] = options.Callback(profile.Id),
            ["response_type"] = "code",
            ["scope"] = scopeConventions.AuthorizationValue(profile, Values(session.RequestedScopesJson)),
            ["state"] = state,
            ["code_challenge"] = DeploymentProofCodec.Challenge(verifier),
            ["code_challenge_method"] = "S256"
        };
        var url = profile.AuthorizationEndpoint + "?" + string.Join('&', parameters.Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value)));
        return new(session.Id, browser, url);
    }
    public Guid IdentifyState(string state, string profile)
    {
        try
        {
            if (state.Length > 8192) throw new UnauthorizedAccessException();
            var parsed = JsonSerializer.Deserialize<OAuthState>(vault.Open("oauth-state", state))!;
            if (parsed.ProfileId != profile || parsed.ExpiresAt <= clock.GetUtcNow().ToUnixTimeSeconds()) throw new UnauthorizedAccessException();
            return parsed.SessionId;
        }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException) { throw new UnauthorizedAccessException(); }
    }
    public async Task<CallbackReturn> Complete(string profileId, string state, string? browser, string? code, string? error, CancellationToken ct)
    {
        var id = IdentifyState(state, profileId);
        var session = await db.Sessions.SingleOrDefaultAsync(x => x.Id == id && x.Status == "AwaitingConsent", ct) ?? throw new UnauthorizedAccessException();
        await Active(session.DeploymentId, null, ct);
        if (session.ExpiresAt <= clock.GetUtcNow() || browser is null || !DeploymentProofCodec.Equal(session.BrowserHash, DeploymentProofCodec.Hash(browser)) ||
            !DeploymentProofCodec.Equal(session.StateHash, DeploymentProofCodec.Hash(state))) throw new UnauthorizedAccessException();
        options.ValidateReturn(session.ReturnUri);
        var (_, manifest, profile) = await registry.Resolve(session.PackageDigest, ct);
        session.Status = "Exchanging"; session.Revision++;
        db.Event(session.DeploymentId, "consent.exchanging", null, session.Revision, clock.GetUtcNow(), session.Id);
        // Consume before calling the provider: a retry cannot reuse an authorization code.
        await db.SaveChangesAsync(ct);
        if (!string.IsNullOrEmpty(error)) return await Finish(session, "Cancelled", "consent_denied", ct);
        if (string.IsNullOrWhiteSpace(code) || code.Length > 8192) return await Finish(session, "Failed", "authorization_incomplete", ct);
        ProviderTokenReceipt receipt;
        try
        {
            receipt = await provider.Exchange(profile, vault.Open("profile:" + profile.Id, profile.ProtectedSecret), code,
                vault.Open("pkce:" + session.Id, session.ProtectedVerifier), options.Callback(profile.Id), ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is HttpRequestException or InvalidOperationException or JsonException or ArgumentException or CryptographicException or OperationCanceledException)
        { return await Finish(session, "Failed", "provider_authorization_failed", ct); }
        // Fake transports and real transports must honor the same bounded receipt boundary.
        Guards.Text(receipt.AccessToken, 8192); if (receipt.RefreshToken is not null) Guards.Text(receipt.RefreshToken, 8192);
        if (receipt.ExpiresIn is < 1 or > 86400 || receipt.Scopes?.Any(x => x.Length > 2048 || x.Any(char.IsControl)) == true) throw new InvalidOperationException("Invalid provider receipt.");
        var requested = Values(session.RequestedScopesJson);
        var granted = scopeConventions.Canonical(profile, receipt.Scopes ?? requested);
        bool Granted(string scope) => granted.Contains(scopeConventions.Canonical(profile, [scope]).Single());
        var connection = new ManagedConnection
        {
            Id = Guid.NewGuid(),
            DeploymentId = session.DeploymentId,
            InstallationId = session.InstallationId,
            PackageDigest = session.PackageDigest,
            ProfileId = profile.Id,
            ProfileRevision = profile.Revision,
            Status = "AuthorizedPendingDiscovery"
        };
        connection.ProtectedCredentials = vault.Seal("connection:" + connection.DeploymentId + ":" + connection.Id,
            JsonSerializer.Serialize(new StoredCredentials(receipt.AccessToken, receipt.RefreshToken, clock.GetUtcNow().AddSeconds(receipt.ExpiresIn))));
        var requiredMissing = manifest.Connections.Single().ScopeSets.Where(x => x.Required).SelectMany(x => x.Scopes).Any(x => !Granted(x));
        // A provider may return a token covering previously granted application scopes. Only requested,
        // reviewed complete sets become service authority; extra token scopes never enable a feature.
        var sets = manifest.Connections.Single().ScopeSets.Where(x => Values(session.ScopeSetIdsJson).Contains(x.Id, StringComparer.Ordinal) && x.Scopes.All(Granted)).Select(x => x.Id).ToArray();
        connection.GrantedScopeSetsJson = JsonSerializer.Serialize(sets);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.Entry(session).ReloadAsync(ct);
        // Recheck after the exchange. Even revocation during an outbound call must not restore authority.
        var active = session.Status == "Exchanging" && await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == session.DeploymentId && !x.Revoked, ct) &&
            await db.Packages.AsNoTracking().AnyAsync(x => x.Digest == session.PackageDigest && !x.Revoked, ct) &&
            await db.Profiles.AsNoTracking().AnyAsync(x => x.Id == profile.Id && x.Enabled && x.Revision == profile.Revision, ct);
        if (!active || requiredMissing) connection.Status = "RevocationPending";
        db.Connections.Add(connection); session.ConnectionId = connection.Id;
        db.Event(session.DeploymentId, connection.Status == "RevocationPending" ? "connection.fenced" : "connection.authorized", connection.Id, 1, clock.GetUtcNow());
        var result = await Finish(session, active && !requiredMissing ? "AuthorizedPendingDiscovery" : "Failed", !active ? "authority_changed" : requiredMissing ? "required_permission_missing" : null, ct);
        await transaction.CommitAsync(ct); return result;
    }
    public async Task<ConnectionReceipt> Redeem(Deployment deployment, RedeemConnection request, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        if (request.Handoff.Length != 43 || request.ReturnVerifier.Length is < 43 or > 128 || request.ReturnVerifier.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~'))) throw new UnauthorizedAccessException();
        var hash = DeploymentProofCodec.Hash(request.Handoff);
        var session = await db.Sessions.SingleOrDefaultAsync(x => x.DeploymentId == deployment.Id && x.HandoffHash == hash && !x.Redeemed, ct) ?? throw new UnauthorizedAccessException();
        if (session.HandoffExpiresAt is not { } deadline || deadline <= clock.GetUtcNow() || session.LocalAttemptId != request.LocalAttemptId || session.ActorId != request.ActorId ||
            session.PackageDigest != request.PackageDigest || !DeploymentProofCodec.Equal(session.ReturnChallenge, DeploymentProofCodec.Challenge(request.ReturnVerifier))) throw new UnauthorizedAccessException();
        await registry.Resolve(session.PackageDigest, ct);
        session.Redeemed = true; session.ProtectedHandoff = null; session.HandoffHash = null; session.Revision++;
        var connection = session.ConnectionId.HasValue ? await db.Connections.AsNoTracking().SingleAsync(x => x.Id == session.ConnectionId.Value && x.DeploymentId == deployment.Id, ct) : null;
        db.Event(deployment.Id, "consent.redeemed", session.ConnectionId, session.Revision, clock.GetUtcNow(), session.Id); await db.SaveChangesAsync(ct);
        return new(session.Id, connection?.Id, session.Status, session.FailureCode, connection is { Status: "AuthorizedPendingDiscovery" } ? Values(connection.GrantedScopeSetsJson) : []);
    }
    public async Task<ConnectionSnapshot> Snapshot(Deployment deployment, Guid id, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        var c = await db.Connections.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        return new(c.Id, c.Status, c.Revision, c.Status is "AuthorizedPendingDiscovery" or "Ready" ? Values(c.GrantedScopeSetsJson) : []);
    }
    public async Task<ConnectionReceipt> Recover(Deployment deployment, Guid id, RecoverConnection request, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        if (request.ReturnVerifier.Length is < 43 or > 128) throw new UnauthorizedAccessException();
        var session = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id && x.Redeemed, ct) ?? throw new UnauthorizedAccessException();
        if (session.ExpiresAt <= clock.GetUtcNow() || session.LocalAttemptId != request.LocalAttemptId || session.ActorId != request.ActorId || session.PackageDigest != request.PackageDigest ||
            !DeploymentProofCodec.Equal(session.ReturnChallenge, DeploymentProofCodec.Challenge(request.ReturnVerifier))) throw new UnauthorizedAccessException();
        await registry.Resolve(session.PackageDigest, ct);
        var connection = session.ConnectionId.HasValue ? await db.Connections.AsNoTracking().SingleAsync(x => x.Id == session.ConnectionId.Value && x.DeploymentId == deployment.Id, ct) : null;
        return new(session.Id, connection?.Id, session.Status, session.FailureCode,
            connection is { Status: "AuthorizedPendingDiscovery" or "Ready" } ? Values(connection.GrantedScopeSetsJson) : []);
    }
    public async Task<ConnectionAttempt> Attempt(Deployment deployment, Guid id, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        var session = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        return View(session);
    }
    public async Task<ConnectionSnapshot> Disconnect(Deployment deployment, Guid id, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        var c = await db.Connections.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        if (c.Status is not ("RevocationPending" or "Revoked")) { c.Status = "RevocationPending"; c.Revision++; db.Event(deployment.Id, "connection.fenced", c.Id, c.Revision, clock.GetUtcNow()); await db.SaveChangesAsync(ct); }
        return new(c.Id, c.Status, c.Revision, []);
    }
    public async Task<ConnectionReceipt> Cancel(Deployment deployment, Guid id, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var session = await db.Sessions.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        if (session.ConnectionId is { } connectionId) await Disconnect(deployment, connectionId, ct);
        session.Status = "Cancelled"; session.ProtectedLaunch = ""; session.ProtectedVerifier = ""; session.StateHash = "";
        session.ProtectedHandoff = null; session.HandoffHash = null; session.BrowserHash = ""; session.Revision++;
        db.Event(deployment.Id, "consent.cancelled", session.ConnectionId, session.Revision, clock.GetUtcNow(), session.Id);
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return new(session.Id, session.ConnectionId, session.Status, "cancelled", []);
    }
    public async Task<ConnectionReceipt> CancelAttempt(Deployment deployment, Guid localAttemptId, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        if (localAttemptId == Guid.Empty) throw new ArgumentException("An original local attempt is required.");
        var existing = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.DeploymentId == deployment.Id && x.LocalAttemptId == localAttemptId, ct);
        if (existing is not null) return await Cancel(deployment, existing.Id, ct);
        // The begin response might have been lost, or its transaction might still be in flight.
        // The same unique attempt fence prevents a late Begin from resurrecting this cancellation.
        var tombstone = new ConsentSession
        {
            Id = Guid.NewGuid(),
            DeploymentId = deployment.Id,
            LocalAttemptId = localAttemptId,
            RequestHash = "cancelled-before-creation",
            Status = "Cancelled",
            FailureCode = "cancelled",
            LaunchHash = DeploymentProofCodec.Hash(DeploymentProofCodec.Random()),
            ExpiresAt = clock.GetUtcNow().AddMinutes(10)
        };
        db.Sessions.Add(tombstone); db.Event(deployment.Id, "consent.cancelled", null, tombstone.Revision, clock.GetUtcNow(), tombstone.Id);
        await db.SaveChangesAsync(ct);
        return new(tombstone.Id, null, tombstone.Status, "cancelled", []);
    }
    public async Task<ConnectionSnapshot> Supersede(Deployment deployment, Guid id, Guid replacementId, CancellationToken ct)
    {
        await Active(deployment.Id, deployment.Revision, ct);
        if (id == replacementId) throw new ArgumentException("A separate replacement is required.");
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var previous = await db.Connections.SingleOrDefaultAsync(x => x.Id == id && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        var replacement = await db.Connections.SingleOrDefaultAsync(x => x.Id == replacementId && x.DeploymentId == deployment.Id, ct) ?? throw new UnauthorizedAccessException();
        if (previous.Status == "Superseded") return new(previous.Id, previous.Status, previous.Revision, []);
        await registry.Resolve(replacement.PackageDigest, ct);
        if (previous.Status is not ("Ready" or "ConnectionRequired") || replacement.Status != "Ready" ||
            previous.InstallationId != replacement.InstallationId || previous.ProfileId != replacement.ProfileId ||
            previous.SubjectHash is null || previous.SubjectHash != replacement.SubjectHash || replacement.InventoryVerifiedAt is null ||
            replacement.InventoryVerifiedAt <= clock.GetUtcNow().AddHours(-1))
            throw new UnauthorizedAccessException("A current provider-verified replacement for the same identity is required.");
        // Revoking the old provider token could revoke the replacement too. Retire only this service authority.
        previous.Status = "Superseded"; previous.ProtectedCredentials = ""; previous.ProtectedInventory = ""; previous.SubjectHash = null;
        previous.GrantedScopeSetsJson = "[]"; previous.LeaseOwner = null; previous.LeaseUntil = null; previous.Revision++;
        db.Event(deployment.Id, "connection.superseded-primary-erased", previous.Id, previous.Revision, clock.GetUtcNow());
        // Version-fence a concurrent replacement disconnect in the same transaction.
        replacement.Revision++;
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return new(previous.Id, previous.Status, previous.Revision, []);
    }
    private async Task<CallbackReturn> Finish(ConsentSession session, string status, string? failure, CancellationToken ct)
    {
        var handoff = DeploymentProofCodec.Random(); session.Status = status; session.FailureCode = failure;
        session.HandoffHash = DeploymentProofCodec.Hash(handoff); session.ProtectedHandoff = vault.Seal("handoff:" + session.Id, handoff);
        session.HandoffExpiresAt = clock.GetUtcNow().AddMinutes(2); session.ProtectedVerifier = ""; session.StateHash = ""; session.BrowserHash = ""; session.Revision++;
        db.Event(session.DeploymentId, "consent.completed", session.ConnectionId, session.Revision, clock.GetUtcNow(), session.Id); await db.SaveChangesAsync(ct);
        return new(session.Id, session.ReturnUri + "#handoff=" + Uri.EscapeDataString(handoff) + "&attempt=" + session.LocalAttemptId.ToString("D"));
    }
    private ConnectionAttempt View(ConsentSession s) => new(s.Id, s.ExpiresAt <= clock.GetUtcNow() && s.Status == "Created" ? "Expired" : s.Status,
        s.Status == "Created" && s.ExpiresAt > clock.GetUtcNow() ? options.PublicOrigin + "/connect/" + vault.Open("launch:" + s.Id, s.ProtectedLaunch) : null, s.ExpiresAt);
    private async Task Active(Guid id, long? revision, CancellationToken ct)
    { if (!await db.Deployments.AsNoTracking().AnyAsync(x => x.Id == id && !x.Revoked && (!revision.HasValue || x.Revision == revision.Value), ct)) throw new UnauthorizedAccessException(); }
    private static string[] Values(string value) => JsonSerializer.Deserialize<string[]>(value)!;
}
