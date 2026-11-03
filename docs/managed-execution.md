# Managed provider execution

The service owns OAuth credentials and reviewed provider mappings. Core owns human approval,
business/agent grants, conversation attachment provenance and frozen-plan approval. A signed
request authenticates Core's attestation; it is not independent evidence of human approval.

## Read stage

`ManagedConnectionClient.ReadOperation` sends an exact signed operation to
`POST /v1/connections/{id}/operations/read`. It supplies the approved package digest,
connection installation, requesting installation, tenant, capability, bound resource,
schema-validated input, Core plan hash and short expiry. The service materializes the
provider URL from its pinned manifest, never a caller-provided URL. Bootstrap discovery,
writes, media mappings and mappings with secret result fields are rejected by this endpoint.
The existing pinned transport disallows redirects, cookies, proxies and nonpublic DNS.

The service independently requires an active exact deployment, current package/profile,
Ready connection, fresh inventory membership, consented scope sets and an operator-owned
`ConnectionService:ExecutionPolicies` entry. Policies identify one deployment and tenant,
an exact package-digest allowlist, explicit `AllowReads`/`AllowResumableMedia` flags and a
revision. The default empty list denies execution. Review and authorize any live policy
configuration separately. Enrolling a customer does not enable either flag.

Ownership checks execute from reviewed declarations before the primary read. The service
rechecks authority after provider I/O and commits a content-free audit under a SQLite
write reservation before releasing a bounded JSON result. The client binds that result
to the signed request hash and enforces an end-to-end deadline without automatic retries.
Authority can change after the service returns, so Core must still revalidate before
accepting the result into its own execution transaction.

## Durable media stage

`ManagedMediaService` supports only reviewed POST `resumable-range.v1` declarations with
an explicit response resource pointer and no secret-result fields. It validates both
input and output schema support before provider I/O. An operation without a resource
query selector requires fresh, complete inventory containing exactly the selected resource.
This restricts reviewed account-level initiation semantics; it does not infer a resource
selector for an ambiguous multi-resource account.

`ManagedMediaRequest` binds tenant, connector/requester installation, connection, package,
capability, resource, input, Core plan hash, approval reference, asset ID/SHA/size/type,
idempotency key and an expiry of at most 24 hours. Core is responsible for verifying the
human decision and the complete media checksum/conversation attachment. Deployment proof
hashes bind the exact transmitted chunk bytes, not independent evidence of that human decision.

A durable Starting claim and unique deployment/idempotency index precede initiation. Lost
or invalid initiation becomes Indeterminate and cannot initiate a replacement. The provider
Location is encrypted and restricted to the exact reviewed initiation origin/path. Clients
receive only a transfer ID and binding hash. Continuations revalidate service authority and
exact policy revision, serialize through a durable lease, and record maximum attempted bytes
before sending. Interrupted chunks require a probe of the existing session. Acknowledgments
cannot regress or exceed attempted bytes; no-progress/failure recovery is bounded to eight.
No internal automatic request retry is performed.

Only the exact signed binary chunk route raises the existing 1 MiB JSON request limit to
8 MiB. It requires application/octet-stream and a bounded Content-Length. It preserves
deployment proofs over exact bytes, nonce replay checks and all other route limits.

Completion requires all bytes attempted, supported declared output schemas, matching response
resource pointers and a final transactional authority/lease check. Results remain encrypted
at rest. Cached initiation/completion receipts also revalidate current authority and the
reloaded transfer inside the same serializable transaction that materializes the receipt.
They cannot return a stale pre-revocation or pre-cancellation result. No cached receipt
initiates another provider exchange. Local cancellation fences continuation and clears the saved session/result; it does
not claim provider-side deletion, processing cancellation or backup erasure. Expiration clears
primary stored media content/session/result under a content-free audit, retaining the
idempotency tombstone so an expired transfer cannot silently restart.

## Adoption and remaining verification

This source candidate does not enable uploads or establish real-provider acceptance. The
existing YouTube connector 0.2.1 upload declaration lacks a response resource pointer and is
intentionally rejected. A new reviewed connector declaration/version is required; do not
change an already approved package's manifest or digest in place.

Protocol 0.6.0 is a local candidate, not a published dependency. Packaged-consumer tests
use an isolated test feed. Publishing, the explicit MediaTransfers schema upgrade,
service-first deployment, exact execution policies and Core adoption each need their
corresponding approval. Upload scopes and business/agent permissions also remain separate.
Publish 0.6.0 only from the final combined read-and-media source revision. The earlier
read-only stage's local 0.6.0 artifact lacks media contracts and must not be released for Core.

The 0.6.0 service has an additive MediaTransfers table/index and requires explicit
`--migrate-store` adoption. Ordinary production startup does not migrate. Tests exercise
synthetic providers and SQLite; Google processing/visibility must still be reconciled by
the agent after an independently approved real upload.
