# Hosting the C-Sweet connection service

The service keeps shared provider credentials off customer installations. Host one service for the
environment, not one Google application per customer. The current code implements managed consent,
bounded resource discovery, refresh, provider revocation and primary credential erasure. It does not
yet implement general managed channel operations, media transfers, service-verifiable action approvals,
or complete backup/processor erasure. Do not launch it as a feature-complete production connector.

## What you need to arrange

1. Choose a stable domain for the service, for example `connections.your-company.example`. The example
   is not a deployed C-Sweet address. Create its DNS record and obtain a valid TLS certificate.
2. Choose an OpenID Connect identity provider for service operators and enterprise administrators.
   Configure a dedicated API audience. The service validates issuer, audience, signature and expiry.
   A customer installation's local login cookie is not a central operator credential.
3. Provide a dedicated persistent disk for the database and Data Protection key ring. Use encrypted
   storage and restrict both to the service identity. The current SQLite implementation supports a
   single service replica on local persistent storage, not multi-replica network-file operation.
4. Supply a current RSA encryption certificate with its private key, at least 2048 bits, through the
   hosting secret manager. This encrypts the persistent Data Protection key ring. Keep the password
   outside source control and set up rotation and secure recovery of historical certificates.
5. Publish the reviewed `CSweet.ConnectionService.Protocol` 0.3.0 NuGet package before releasing the
   corresponding C-Sweet host. Host verification uses a packed package, never sibling source references.
6. Register the provider application, publish actual product/privacy/terms pages, complete applicable
   verification, and authorize a real pilot account. Google is one OAuth provider, not the service core.

## Build and configure

Run `pwsh scripts/Test-Release.ps1`, then publish the host:

```powershell
dotnet publish src/CSweet.ConnectionService -c Release -o artifacts/publish
```

Alternatively build the supplied Dockerfile. Before a production release, pin and scan the exact
Microsoft runtime/container image digest. The Dockerfile uses a non-root runtime user; Docker image
build and production deployment are separate from the local .NET test results.

Supply configuration through environment variables or your deployment secret provider:

```text
ConnectionService__PublicOrigin=https://YOUR-ACTUAL-SERVICE-DOMAIN
ConnectionService__Database=Data Source=/data/connections.db
ConnectionService__KeyRingDirectory=/data/keys
ConnectionService__ProtectionCertificatePath=/run/secrets/keyring-encryption.pfx
ConnectionService__ProtectionCertificatePassword=<secret-manager value>
ConnectionService__OperatorAuthority=https://YOUR-TRUSTED-OIDC-ISSUER
ConnectionService__OperatorAudience=csweet-connections-operators
```

Do not commit an `.env` file containing real values. Outside Development the service requires encrypted
keys and disallows development store initialization and loopback return exceptions. Persist the disk
across replacement deployments; losing the key ring makes existing authorizations unrecoverable.

Initialize or upgrade storage explicitly while ordinary service traffic is stopped:

```powershell
dotnet CSweet.ConnectionService.dll --migrate-store
```

Then start normally with `dotnet CSweet.ConnectionService.dll`. Ordinary production startup refuses an
old schema instead of silently modifying it. Back up before upgrades, test restores in isolation, and
apply revocation/deletion fences before a restored service can serve traffic. An encrypted backup
still contains provider-derived data and needs its own retention and deletion controls.

## TLS and reverse proxies

The service requires HTTPS requests. Use direct Kestrel TLS with a separately configured server
certificate, or a private reverse proxy whose exact IP is configured with
`ConnectionService__KnownProxyAddresses__0`. The key-ring encryption certificate is not automatically
the web server certificate.

Only configured proxies may supply forwarded protocol/client-address headers, with one forwarding
hop. Block direct public access to the backend HTTP port. At the proxy, overwrite forwarded headers
rather than appending untrusted incoming values. Never solve proxy failures by globally trusting
forwarded headers or disabling the service's HTTPS requirement.

Disable URL-query/header/body logging on proxy routes `/connect/*`, `/oauth/callback/*`, `/v1/*` and
`/operator/*`. Do not put OAuth codes, state, browser cookies, proof headers or bearer credentials in
analytics or error reporting. Check `/health` and `/features` through the actual public TLS endpoint.

## Set up operator identity

Tokens for service administration must contain a validated `sub` and the configured audience.

- `csweet_role=connection-service-operator` authorizes provider configuration and immutable package review.
- `csweet_role=enterprise-administrator` or `connection-service-operator`, plus `csweet_tenant`, authorizes
  enrollment/key rotation/revocation only for that tenant.

Issue those roles only from the trusted control-plane identity provider. Do not accept roles supplied
by a plugin, arbitrary cloned host, or unsigned browser payload. There is no shipped shared operator
password, anonymous enrollment route, or all-customers API key. The current pairing UI uses operator
enrollment plus verified deployment proof; a fully interactive control-plane sign-in/pairing experience
still needs to be completed.

## Configure Google without distributing its secret

Create a web OAuth client for agent workflows and register this exact callback using the real domain:

```text
https://YOUR-ACTUAL-SERVICE-DOMAIN/oauth/callback/com.csweet.google.youtube
```

The previously created `https://localhost:7033/api/plugin-connections/oauth/callback` belongs to the
local development backend. It is not the managed service callback. Keep development and production
provider registrations separate. Enable the APIs and base scopes described in the host repository's
Google setup guide; progressive access remains plugin-declared and human-initiated.

Run `scripts/Import-GoogleOAuthClient.ps1` with the real service origin, profile ID and local export
file. It prompts for a central operator token with hidden input, sends the export only to that HTTPS
service, validates Google's endpoints and exact callback, and returns public profile metadata only.
Do not paste client secrets or operator tokens into chat, command arguments, manifests or Git. The
import adapter is in `CSweet.ConnectionService.OAuth.Google`; another provider adds its own adapter
only when its export format or protocol behavior needs one.

An import configures an application identity; it does not approve a connector package. Review each
immutable package digest, manifest SHA-256, source repository/commit, provider destinations and profile
binding, then register it through authenticated `POST /operator/packages`. A claimed publisher name
or copied profile identifier conveys no authority. Test the reviewed digest that the installed host
actually reports, not an uncommitted sibling manifest.

## Pair a C-Sweet installation

Configure these non-provider settings on the C-Sweet backend:

```text
CSweet__PluginConnections__Managed__Enabled=true
CSweet__PluginConnections__Managed__ServiceOrigin=https://YOUR-ACTUAL-SERVICE-DOMAIN
CSweet__PluginConnections__Managed__ReturnUri=https://YOUR-CSWEET-UI/settings/plugins/managed-return
CSweet__PluginConnections__Managed__RegistrationPath=/restricted-host-state/managed-registration.dat
```

The registration file holds a per-deployment private key protected by that host's Data Protection key
ring. Protect the host key ring/database and restrict this directory too. The shared Google secret and
Google access/refresh tokens never go into this file or the host configuration.

1. Rebuild/restart the host and open `/settings/connections` as its enterprise administrator.
2. Choose **Prepare pairing**. This creates a deployment key and shows only its public pairing details.
3. Using an authorized central tenant administrator token, submit `POST /operator/deployments` with
   `name`, `publicKey`, `keyId`, and `returnUris` containing exactly the displayed return URI. The
   service chooses the tenant from the validated token; do not trust a tenant supplied by the host.
4. Enter the returned deployment ID, tenant ID and revision in the host, then choose **Verify and
   finish pairing**. The host proves possession of its key to the actual service before saving the binding.
5. Install/review an approved connector and choose **Connect account**. A real provider browser consent
   returns an opaque handoff. C-Sweet checks the original human/browser and redeems it over the signed
   backchannel, then imports sanitized resources. Sharing with businesses/agents is still separate.

Use HTTPS returns. A service owner can explicitly allow an exact local HTTPS browser return without
exposing Headquarters publicly or switching the service to Development. See
[local browser returns](local-browser-returns.md) for the default-off allowlist and independent exact
deployment enrollment. The older `AllowDevelopmentLoopbackReturns=true` switch now fails startup;
replace it with reviewed exact HTTPS entries. HTTP and arbitrary loopback ports are not supported.
Public provider endpoint/DNS validation, the Google callback and proof requirements are unchanged.

Customer-owned profiles may be explicitly listed under
`CSweet:PluginConnections:Managed:CustomerOwnedProfiles`. They use the independent local vault-backed
OAuth backend. Outages never silently switch a managed connection to local credentials or transfer tokens.

## Acceptance before launch

Run authorized real-provider consent, denial, progressive consent, interruption/restart, scoped
business sharing, reconnect, disconnect and actual provider revocation. Keep mock tests and real
acceptance results separate. Confirm backup/processor cleanup independently of primary credential
erasure. Do not advertise uploads, replies, or other general managed operations until their central
approval, request-plan enforcement, media transport and reconciliation work is implemented and accepted.

Complete independent security review, key/certificate rotation, proxy log inspection, per-provider
quota controls, recovery/restore and incident procedures. Kubernetes/cloud scale-out and cloud-KMS
adapters are not implemented by the initial single-replica hosting package.


For version 0.4.0 owner administration without an external IdP, see [owner administration](owner-administration.md). OIDC operator routes now require explicit `EnableOidcAdministration=true`; do not assume they are enabled by setting only an issuer.
