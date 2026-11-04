# Compatible managed-connection adoption

`ConnectionAdoptionService` implements a narrow provider-neutral alternative to destructive
disconnect/reconsent during a compatible connector package upgrade. It has no vault or provider
transport dependency. Existing credentials and inventory stay encrypted under the same connection
identity. Original consent sessions, scopes, subject and historical erasure obligations are retained.

The paired deployment signs an exact source/target installation and approved package binding,
expected source connection revision, original actor/consent session and expected provider-profile fingerprint.
`Preview` checks current `Ready` provider-verified inventory within its unchanged declared authorization-check window, no maintenance
lease, no unresolved media transfer and no other target-installation connection. Both registry
approvals must be active, belong to the same repository and match the current provider/profile.
The source connection's deployment/installation/digest must match the signed request exactly.

`CompatibleConnectionContract.Require` is deliberately conservative. Apart from package version
and provider operations, all root declarations must be structurally identical, including unknown
future fields, provider destinations, real scope definitions, identity/discovery/lifecycle policy,
capability/schema declarations, setup, configuration and web access. Every operation executable
under the existing granted scope sets must also be structurally identical. Changing an operation
behind a scope that was never granted does not create that scope or an execution policy. Root declaration array
order changes are rejected rather than guessed equivalent; executable operations are compared by
capability so reordering that collection does not change its meaning. The registry's SDK validation remains
mandatory; this helper is not a replacement manifest validator.

The deployment signer attests Core's installation lineage and human identity. The service checks
the existing actor correlation but cannot independently prove a browser click or business/agent
permissions. Core must enforce the authenticated original administrator's exact review, native
lineage/resource/grant inventory and concurrency. No token or public client ID proves those rights.

Adoption and its content-free request/receipt/audit commit in a SQLite serializable write fence.
The connection revision advances so in-flight old-bound read/media results fail revalidation. Old
package/installation execution requests are rejected; a new target policy must be granted separately.
Current receipt status includes the actual current installation/digest and state, so a receipt is
neither an execution grant nor a promise that authority can never subsequently be revoked.

The adoption ID is idempotent only for the exact request/review. `Status` recovers the same durable
receipt within its deployment, without another provider or adoption request. `Cancel` inserts an
immutable tombstone when adoption has not committed; a late adoption with that ID is rejected.
If adoption already committed, cancellation returns its adoption receipt rather than pretending
to roll back or re-enable the old binding. Core must reconcile forward or keep execution fenced.
The old original consent's cancellation endpoint still fences the same adopted connection.

Deployment order: separately approve/release Protocol 0.7.0; explicitly migrate and deploy service
0.7.0 before deploying its Core consumer. Package approval and execution policy for the target remain
independent operator actions. Missing/old service endpoints must leave the existing account intact.
No migration, deployment, package publication, live adoption or provider consent is performed by
the tests or this source change. Backup/processor erasure handlers are not supplied by adoption.
