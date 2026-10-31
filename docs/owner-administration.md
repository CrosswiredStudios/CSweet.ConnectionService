# Self-hosted owner administration

Version 0.5.0 adds optional content-free failure diagnostics in `X-CSweet-Owner-Diagnostic`.
The service generates a correlation ID and emits only fixed stage/code/type labels, HTTP status
and bounded elapsed time. Authorization failures always use the generic authorization stage.
The Protocol client accepts only the versioned canonical format and known labels; malformed or
absent metadata is ignored. Failure bodies are never read or forwarded. Existing clients still
receive the same failure bodies, and new clients support services without diagnostics.
These hints do not prove a mutation rolled back and never authorize an automatic retry.
This feature does not change log destinations or enable body/header/exception-message logging.

Version 0.4.0 adds a separate owner control plane. It does not require an external identity provider. `EnableOidcAdministration` defaults to false; existing deployments that intentionally use `/operator` must explicitly enable it and keep valid OperatorAuthority/OperatorAudience configuration. Existing customer `/v1` proofs and Google OAuth consent remain unchanged.

Before starting version 0.4.0, back up protected SQLite/key storage and run the existing explicit `--migrate-store` operation. OwnerBinding, OwnerGrant and OwnerNonce are added atomically. No default owner or capability is granted by migration.

The C-Sweet owner UI prepares a distinct protected P-256 key and a public bootstrap JSON document. Review the exact service origin, binding/key, user GUID, capabilities and tenant scope at the service host. The local command is `CSweet.ConnectionService --owner-admin /absolute/path/to/reviewed-command.json`, using the same protected service configuration and OS authority as the service. This command exits without starting HTTP listeners. Bootstrap accepts a fresh binding and expectedRevision 0. It is not a public enrollment endpoint.

`LocalOwnerCommand` supports bootstrap, grant, revoke-grant and revoke-binding. Subsequent grant/revocation operations require the current grant or binding revision. All commands require the exact service origin and binding ID. Capabilities are credentials.import, packages.approve, deployments.enroll and deployments.revoke. Tenant scope `*` explicitly grants global scope; provider credential/package capabilities require it. A tenant-specific user can enroll/revoke only that tenant. Owner grants are managed locally, not by customer administrators or the remote owner API.

For recovery while C-Sweet is offline, use local revoke-grant/revoke-binding, then grant a replacement user or bootstrap a fresh installation/key. Old keys remain revoked. Preserve database backups and Data Protection/encryption keys. Read public binding/grant identifiers and revisions from the protected local database or retained local command results; no public credential enumeration endpoint is provided.

The owner API uses existing signed proof primitives with a distinct header, audience, binding registry and replay store. Every request checks exact origin, short expiry, nonce, binding/grant revision, user capability and tenant. Authority checks, nonce consumption, mutation and content-free audit share one database transaction. Both enrollment and rotation reject owner keys as customer keys. An owner backend signature asserts its current session checks; it does not independently prove a human approved the action. Compromise of a trusted owner server compromises its explicitly delegated capabilities. Minimize grants and use local revocation for recovery.

Credential import is typed and returns only public availability metadata. Never log request bodies, put credential documents in command arguments, or enable HTTP body tracing. The C-Sweet UI checks Identity sessions, current roles and CSRF before signing. This pilot does not implement mobile pairing, general provider actions, or centralized action approval.

Live storage/permissions, grants, launchd, routing/DNS and Google credentials remain separate operator deployment decisions. No live configuration is included in this change.

For credential imports and connector approval using local OS authority without adding global owner
permissions, see [local provider setup](local-provider-setup.md). Live imports and approvals require
separate review of the exact credential source and immutable package/profile binding.
