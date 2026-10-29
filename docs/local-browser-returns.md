# Exact local HTTPS browser returns

Headquarters can remain on the account owner's computer while the connection service and Google's
registered callback use public HTTPS. After consent, the service redirects the browser back to
Headquarters. It does not fetch, probe or resolve the browser-return destination.

The service owner must explicitly configure every permitted local HTTPS address. The default is an
empty allowlist. For the Windows UI's HTTPS launch profile, the proposed entry is:

```text
ConnectionService__AllowedLocalBrowserReturnUris__0=https://localhost:7125/settings/plugins/managed-return
```

This example is not deployed configuration or permission to enroll an installation. Restart the
reviewed service with its protected configuration after separately approving the change. Keep the
service in Production with its existing public origin, encrypted storage and trusted proxy settings.

Allowlist entries must be canonical absolute HTTPS URLs on `localhost` or a literal loopback address.
The whole string, including host, port, path and case, is matched exactly. Each IP spelling is a
separate entry. At most twenty distinct entries are permitted. There are no wildcard hosts, ports,
paths, prefixes or automatically discovered callback ports. HTTP, user information, query strings,
fragments, whitespace, encoded spellings and path normalization are rejected. The older unrestricted
`AllowDevelopmentLoopbackReturns=true` configuration is rejected at startup; omit it or leave it false.

The same exact URL must also be enrolled for the particular customer deployment by an authorized
operator/owner. The owner allowlist does not perform enrollment or grant any deployment authority.
Consent begin, browser launch and provider callback recheck the configured return policy. Removing an
entry blocks those pending steps before provider exchange; it does not silently revoke existing
provider connections. Use the existing explicit disconnect/revocation flow for that separate action.

On the browser computer, HTTPS must use a trusted certificate valid for the chosen local hostname.
For Windows' existing `localhost` developer certificate, use the literal `localhost` URL, not an IP
alias. Run the UI's HTTPS profile and point its downloaded WebAssembly configuration at the API's
HTTPS endpoint. Selecting HTTPS only for an orchestration dashboard does not configure these client
settings. Authentication cookies, current user/session checks and CSRF protection remain required.

The Google redirect URI is still the service's public callback, for example:

```text
https://connections.c-sweet.com/oauth/callback/com.csweet.google.youtube
```

The local URL is the later browser return, not a Google callback or a native application's dynamic
HTTP-loopback OAuth exception. It never receives Google access/refresh tokens, application secrets
or the provider authorization code. The existing fragment handoff lasts two minutes, is single-use,
and requires the original attempt, actor, return verifier and signed deployment request to redeem.
Core additionally binds its completion to the authenticated user, original browser cookie and session.

This policy does not apply to service origins, provider authorization/token/revocation URLs, package
repository URLs or outbound HTTP. Their existing public/DNS and SSRF guards are unchanged. Review the
actual exact configuration, owner grants and enrolled installation separately; this source change
does not create keys, configure a live Mac service, establish real Google consent, or require a new
Protocol package version.
