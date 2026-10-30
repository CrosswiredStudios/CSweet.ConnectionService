# Local provider setup without remote administrator grants

A host administrator can import provider application credentials and approve one reviewed connector
using the installed service account, Production configuration and existing encrypted store:

```sh
CSweet.ConnectionService --contentRoot /absolute/protected/config --local-setup /absolute/protected/command.json
```

This exits without starting HTTP listeners. It does not migrate the database, enroll a customer,
create an owner grant, enable provider APIs or consent to any account. The existing remote owner
permissions and optional OIDC routes are unchanged. Keep the service origin, storage and encryption
settings identical to the running service. Run under its OS account; do not run with an administrator's
unrelated configuration/key ring. First-time schema setup remains a separate approved operation.

All input files must be absolute paths to regular files. On Unix, use owner-only `0600` or root-owned,
service-group-readable `0640`; other-user access and group writes are rejected. Keep input directories
under trusted local administrator control. On Windows, the operator must restrict ACLs to the service
identity and administrators; Unix mode checks do not establish Windows ACL safety. Never put JSON,
client secrets or access tokens in shell arguments, source control or logs. This is a file permission
check, not a sandbox against an administrator or someone who can replace trusted input directories.

## Import one credential document

The command contains only a path to the separately protected provider export:

```json
{
  "action": "import-credentials",
  "serviceOrigin": "https://connections.example.com",
  "credentialImport": {
    "profileId": "com.csweet.google.youtube",
    "format": "google-web-client",
    "credentialFile": "/absolute/private/google-web-client.json",
    "expectedProfileRevision": 0,
    "expectedSecretVersion": 0
  },
  "packageApproval": null
}
```

Zero/zero requires a new profile. For an existing profile, review its current public revision and
secret version locally, then supply both exact values. A stale command fails; it cannot silently
rotate a secret on repeat execution. Rotation still rejects a changed application/project/endpoints
or disabled profile. The existing Google reader validates the export and exact public service callback.
The registry encrypts the secret and saves its content-free audit event in the same transaction.
No provider network request is made during import. Rotation increments secret version but does not
expand customer grants or establish Google consent.

## Approve one immutable connector declaration package

```json
{
  "action": "approve-package",
  "serviceOrigin": "https://connections.example.com",
  "credentialImport": null,
  "packageApproval": {
    "packageDigest": "REVIEWED_CONNECTOR_DECLARATION_SHA256",
    "manifestSha256": "EXACT_MANIFEST_UTF8_SHA256",
    "manifestFile": "/absolute/protected/reviewed-csweet-plugin.json",
    "profileId": "com.csweet.google.youtube",
    "expectedProfileRevision": 1,
    "repositoryUrl": "https://github.com/owner/repository",
    "sourceCommit": "REVIEWED_LOWERCASE_COMMIT"
  }
}
```

Use the exact repository spelling, commit and manifest bytes from the installation's package review.
This path supports `connector-declarations.v1`, not NuGet archive hashes or executable agent packages.
It recomputes the host's declaration digest over the compact JSON fields `format`, `repository`,
`commit`, `manifest`, in that order, and compares both hashes before mutation. It then uses the existing
SDK manifest and active provider-profile validation. Source authenticity and intended capabilities
still require human review; a matching hash alone does not establish trusted provenance.

An identical active approval is a no-op. Revoked or conflicting bindings are not overwritten.
Approval and audit are atomic. Credentials and package approvals are separate commands, so an approval
failure does not undo a successful earlier credential import. Review actual state before recovery.

## Results and recovery

Success prints only a typed result: action, profile ID/revision, secret version (import only), package
digest (approval only), and whether state changed. No credential document, client secret, arbitrary
provider response or exception payload is printed. Local CLI logging providers are disabled, including
during initialization. Failure prints a fixed diagnostic and exits nonzero. Mixed local-setup,
owner-admin, migration or arbitrary command switches are rejected.

The transaction may have committed before a process/output interruption. Inspect the protected
`Profiles` public metadata, `Packages` binding and content-free `Events` audit locally before any retry.
Do not query `ProtectedSecret`, restore old keys or broaden remote owner grants as a workaround.
No Protocol package version changes are needed: these contracts are host-local and not published.
