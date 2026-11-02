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

## Remaining implementation and adoption

This first stage does not implement durable media sessions, chunk relay, Core transport
integration or agent video handoff. It does not enable uploads or prove real-provider
acceptance. Those remain required before the user's upload goal is complete.

Protocol 0.6.0 is a local candidate, not a published dependency. Packaged-consumer tests
use an isolated test feed. Publishing, migration (if later media tables are added),
service-first deployment, exact execution policies and Core adoption each need their
corresponding approval. Upload scopes and business/agent permissions also remain separate.
