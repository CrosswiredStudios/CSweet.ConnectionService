# Remaining managed connection work

Version 0.3.0 implements module separation, deployment trust, central OAuth custody, bounded inventory,
serialized refresh, provider-confirmed revocation and primary credential erasure. The host now has managed
consent/return/import paths and administrator pairing controls. The local backend remains separate and the
conversational agent is unchanged. This is not a completed general managed connector or production release.

## Next implementation increments

1. Finish managed/local materialization and secret-response conformance for ordinary provider operations.
   Schema validation is shared; bootstrap discovery is implemented but is not a general execution API.
2. Finish control-plane browser sign-in/pairing, key rotation/revocation controls and signed expiring
   profile metadata. Current pairing requires an authorized central enrollment followed by proof verification.
   Add integrated browser acceptance across separate service/host processes, including real Google.
3. Complete distributed cleanup receipts, backup/processor deletion, retention deadlines and restore
   fences. `Revoked` confirms provider revocation and primary credential erasure, not every external copy.
   The host records a separate managed-service backup obligation instead of fabricating confirmation.
4. Implement independently verified exact-plan execution, service-verifiable approver identity and
   owner policies. A signed self-hosted request cannot attest that a human approved its mutation.
   Add media streaming, per-chunk checks, resumable checkpoints, secret extraction and reconciliation
   before enabling writes. Recheck every request/chunk and expire execution leases within 30 seconds.
5. Complete consumer notifications, per-provider/tenant quotas and circuit breakers. The ingress rate limiter
   is not provider quota scheduling. Add cloud KMS, production migrations/database concurrency tests,
   certificate rollover, production proxy acceptance, backup/restore and incident exercises. Explicit
   SQLite upgrades and exact proxy-address configuration exist; scale-out database/KMS adapters do not.
6. Publish reviewed protocol/client packages before downstream package pins change. Register the
   actual provider clients/callbacks, publish applicable policies, satisfy verification/audits, run
   a real authorized install-to-disconnect story and obtain security/operational acceptance.

## Current acceptance evidence

Automated HTTP tests cover the YouTube declaration and alternate workspace provider, operator JWT
roles/audiences, tenant/deployment isolation, exact proof bindings/replay/body tampering, immutable
approvals, profile/key rotation and revocation, PKCE/browser state, partial/denied consent, bounded
handoffs, concurrent callbacks, SQLite/key-ring restart recovery, expiry, fenced disconnect and
log/response credential non-disclosure. Reviewed inventory calls, serialized refresh and revocation execute
against deterministic fake providers. They do not prove real provider APIs, physical backup erasure,
production identity/KMS, the integrated managed host browser flow or Google acceptance.

Discovery's final inventory/outbox commit uses a short serializable SQLite transaction after
provider I/O, reloading and rechecking status, lease ownership/expiry, deployment revision and
registry authority before saving. Deterministic independent-context tests cover disconnect,
completed revocation, replaced/expired leases, deployment rotation, package/profile fencing,
the validation-to-save writer gap and rollback event leakage during lease cleanup. Expected DNS,
blocked-destination and timeout failures retain pending revocation credentials and the bounded
retry deadline; shutdown cancellation and unexpected provider bugs still propagate.

The latest local release check passed 93 tests, packed the unchanged protocol 0.3.0, verified its
NuGet metadata, and restored/executed a fresh package-only consumer. The public protocol API is
unchanged; these fixes are in the non-packable OAuth service and its tests.
These are local artifacts only: no package publication, public service deployment or real account
authorization has been performed.
