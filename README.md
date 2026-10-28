# C-Sweet connection service

Version 0.3.0 separates the provider-neutral service host from connection protocols and provider
adapters. Shared provider application secrets and OAuth tokens stay at the service, not in customer
clones or agent runtimes. The C-Sweet host integrates managed consent and account-resource import;
customer-owned local credentials remain a separate explicit mode.

## Projects

- `CSweet.ConnectionService` is the composition root and executable.
- `CSweet.ConnectionService.Core` discovers statically trusted connection modules through
  `IConnectionModule`. Future mobile/device-link services can register separate modules without
  becoming OAuth providers. No mobile-link feature is implemented yet.
- `CSweet.ConnectionService.OAuth` implements the generic OAuth protocol, deployment proofs,
  reviewed plugin/profile registry, credential vault, inventory, refresh and revocation.
- `CSweet.ConnectionService.OAuth.Google` understands Google's downloaded web-client credential
  format, scope aliases/order and project revocation grouping. It does not implement YouTube channel behavior.
- `CSweet.ConnectionService.Protocol` is the versioned BCL-only host client and shared bounded
  schema validator. It exposes no provider-token download or arbitrary authenticated HTTP endpoint.

Reviewed connector declarations supply scopes, identity/resource discovery, exact GET destinations
and projections. The service loads no plugin executable and no LLM. Operators approve immutable
package digests and profile bindings independently of a publisher name. A host signature proves
its deployment identity, not that a human approved a channel mutation.

## Implemented account setup

The service supports tenant-bound deployment enrollment, rotation/revocation, exact return addresses,
PKCE, browser-bound single-use state, scoped consent, encrypted credential custody, single-use
handoffs and proof-bound recovery receipts. Native C-Sweet checks the initiating human and browser,
imports sanitized resources, and leaves business sharing and agent bindings ungranted until reviewed.

Discovery is resumable and bounded to plugin-declared bootstrap reads, with input/output validation,
pagination deduplication, encrypted checkpoints and authenticated identity evidence. Refresh uses
durable leases and fences uncertain outcomes. Provider-confirmed revocation precedes primary
credential erasure; backups and processors require separate cleanup evidence. Abandoned grants
are fenced rather than retained indefinitely.

The transport pins public DNS and disallows redirects, proxies, cookies, private-network destinations
and oversized responses. Logs/results never intentionally expose provider credentials, proof keys,
OAuth state/codes, launch handles or handoffs. The operator import script sends a Google export only
to the configured HTTPS service and never writes its secret into repository files.

## Not yet complete

General managed channel operations, service-verifiable action decisions/standing policies, resumable
media transfer, complete distributed cleanup receipts, quota scheduling, cloud KMS and production
security/real-provider acceptance remain unfinished. Managed discovery is not permission for uploads,
comment replies or other mutations. Those operations fail closed; do not present this as a completed
production YouTube connector. The conversational agent is unchanged.

## Verify and host

Run `pwsh scripts/Test-Release.ps1` with .NET 10. It tests real HTTP/SQLite/proof paths using fake
providers, packs protocol 0.3.0, checks NuGet metadata and restores a fresh package-only consumer.
Tests include an alternate provider and an independent non-OAuth test module. They do not prove real
Google acceptance or physical backup deletion.

Follow [the hosting runbook](docs/hosting.md) for TLS, storage, operator identity, explicit schema
upgrades, provider application registration/import, immutable package approval and host pairing.
For the proposed `connections.c-sweet.com` deployment, use the [Mac Studio/Cloudflare guide](docs/hosting-mac-studio.md).
The Dockerfile runs a non-root .NET host. No cloud resources, public repository, package publication
or live provider connection are created by local verification.

See [remaining work](docs/remaining-work.md) for the release gaps. Never commit client secrets,
operator tokens, private keys, certificates or real account data. OAuth guidance:
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) and
[Google credential storage](https://developers.google.com/identity/protocols/oauth2/resources/best-practices).

## License and independent hosting

The source and protocol package are licensed under [MIT](LICENSE), copyright 2026 C-Sweet.
Independent operators supply their own authorized provider applications, secrets, registered callbacks
and administrator identity. No official C-Sweet credentials or customer data are distributed here.
Software licensing does not identify a running service as officially operated by C-Sweet, and this
repository makes no claim that modified forks cannot copy names or artwork.
