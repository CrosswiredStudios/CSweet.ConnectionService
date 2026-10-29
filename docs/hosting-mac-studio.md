# Host on your Mac Studio behind Cloudflare

Proposed address: `https://connections.c-sweet.com`. This is a recommendation, not a deployed service.
No DNS, Cloudflare, Mac Studio, Google credentials, or customer installation has been changed by this work.

The Mac Studio runs one provider-neutral service. Google is its first application adapter; future
mobile pairing or other connection protocols can use separate modules. Customers install a plugin,
choose **Connect account**, approve the provider's own consent screen, and return to C-Sweet.

The account-connection/import path is implemented. General managed provider actions and their approval
and media boundaries remain incomplete. Use this guide to prepare a controlled pilot, not a public launch.

## 1. Reserve the address

Use your existing Cloudflare Tunnel account and choose the public hostname `connections.c-sweet.com`.
Namecheap is your domain registrar; DNS records belong wherever the domain's authoritative nameservers
point. If those are already Cloudflare, add the hostname there, not in Namecheap's inactive DNS panel.
If Namecheap still serves authoritative DNS, review the existing DNS/mail records and your Cloudflare
zone setup first. Do not change nameservers or replace working records blindly.

Cloudflare's [tunnel DNS guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)
explains the tunnel CNAME and account requirements. Registering the domain and running a tunnel are
separate tasks. Do not publish an A record exposing your home IP or open a router port for this service.

## 2. Prepare private storage and secrets

Run under a dedicated macOS service account. Give it its own private persistent directory, outside
Git, for `connections.db`, Data Protection keys and the encryption certificate. Enable disk encryption
and restrict the directory to that account. Back up it securely; losing the keys loses existing grants.

Provide a current RSA key-ring encryption certificate with its private key, at least 2048 bits, through
your deployment's secret handling. Keep its password and Google's client JSON outside the repository.
This certificate encrypts stored keys; it is not the public website's TLS certificate.

Use a single service replica with SQLite on the Mac's local disk. Do not put the database on a network
share or start several copies against it. A home-hosted service also needs automatic restart, updates,
disk monitoring, reliable power and Internet; if the Mac or tunnel is down, customer connections fail.

## 3. Choose administrator sign-in

Two different sign-ins are involved:

- **Customers connecting Google:** Google's consent page grants C-Sweet access to their accounts.
- **You administering the service:** a trusted OpenID Connect issuer identifies who can configure
  shared application credentials, review plugin packages and enroll customer deployments.

The second is not implemented by a Cloudflare Tunnel or by downloading Google's client JSON.
Choose/configure an OIDC identity service that issues the dedicated audience and administrator/tenant
claims documented in [the main hosting runbook](hosting.md#set-up-operator-identity). This choice is
still outstanding. Do not substitute an anonymous endpoint, a shared customer API key, or plugin-supplied roles.

Cloudflare Access can be an additional operator-edge control, but its login cookie alone is not the
service's administrator token. Do not put a blanket Access/browser challenge over customer OAuth
callbacks or signed backchannel APIs: that would interrupt account consent and machine requests.

## 4. Build the service for the Mac

On the Mac, install the .NET 10 SDK and PowerShell 7 for the verification/import scripts. From this repository:

```sh
pwsh scripts/Test-Release.ps1
dotnet publish src/CSweet.ConnectionService -c Release -r osx-arm64 --self-contained true -o artifacts/mac-service
```

Copy the resulting application to its service directory. Do not deploy the test harness. Use a `launchd`
service or your existing process supervisor to keep it running, loading real secrets from protected
deployment configuration rather than a committed plist or shell history.

Configure the variables in [Build and configure](hosting.md#build-and-configure). For a native service
and native `cloudflared` on the same Mac, use these additional/non-secret values:

```text
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://127.0.0.1:7085
ConnectionService__PublicOrigin=https://connections.c-sweet.com
ConnectionService__KnownProxyAddresses__0=127.0.0.1
```

Keep the database, key-ring paths and secret values specific to your Mac. Run the published binary
once with `--migrate-store` while ordinary traffic is stopped, then start normally. Startup refuses
an old schema. The supplied Dockerfile is an alternative, not required for the native Mac deployment;
container networking/proxy addresses differ and must be configured explicitly if you choose it.

## 5. Route the tunnel

Add a published application/public-hostname route on your existing tunnel:

```text
Hostname: connections.c-sweet.com
Origin service: http://127.0.0.1:7085
```

This assumes `cloudflared` runs natively on the same Mac. If it runs in a container, its localhost is
not the Mac's localhost; do not compensate by exposing an unprotected backend on all interfaces.
The tunnel must preserve the original HTTPS protocol through the explicitly trusted loopback proxy.
Verify `/health` and `/features` through the public hostname. If HTTPS checks fail, inspect the actual
proxy configuration; never disable the check or globally trust forwarded headers.

Disable caching and redact request query strings, cookies, authorization/proof headers and bodies
for this hostname in your proxy/logging/analytics systems. OAuth callbacks contain one-time codes
and state. Browser challenges must not replace API responses. See Cloudflare's
[origin configuration](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
and the service runbook's proxy restrictions.

## 6. Register the central Google callback

For the managed Google web client, register this exact redirect in Google Cloud:

```text
https://connections.c-sweet.com/oauth/callback/com.csweet.google.youtube
```

The local development callback is different. Import the downloaded client JSON using
`scripts/Import-GoogleOAuthClient.ps1` only after the real HTTPS service and operator identity work.
It prompts for the operator token privately. Do not email the JSON, paste its secret into chat, or
copy it into a customer clone. Keep production and development registrations separate.

Enable YouTube Data API v3 and YouTube Analytics API, configure the consent screen/test users, publish
real privacy/terms pages, and complete applicable Google verification/audits before opening access.
[Google's web-server guidance](https://developers.google.com/identity/protocols/oauth2/web-server)
explains exact redirects and provider consent; [its best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices)
cover secret storage, incremental consent and revocation.

## 7. Pair and test C-Sweet

Publish the reviewed protocol package before distributing the updated host. Configure the host's
managed service origin as `https://connections.c-sweet.com` and its exact UI return address as
`https://YOUR-CSWEET-UI/settings/plugins/managed-return`. Pair it through `/settings/connections`
using the authenticated enrollment steps in the main runbook. A local HTTPS Headquarters UI can use
the explicit [local browser-return policy](local-browser-returns.md) without becoming publicly hosted.
Approve the actual immutable connector
digest/profile binding centrally; merely configuring Google's credentials is not package approval.

Then test install → Connect account → Google consent → channel import → explicit business sharing →
reconnect → disconnect and independently confirm provider revocation. Use an authorized pilot account.
The current automated tests use fake providers; no real Google connection or Mac/Cloudflare acceptance
has been performed. Complete the remaining execution, cleanup and security acceptance work before launch.


For version 0.4.0 owner administration without an external IdP, see [owner administration](owner-administration.md). OIDC operator routes now require explicit `EnableOidcAdministration=true`; do not assume they are enabled by setting only an issuer.
