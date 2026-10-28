# Publishing the protocol package

The package is `CSweet.ConnectionService.Protocol`; the OAuth service is not a NuGet package.
Run `pwsh scripts/Test-Release.ps1` to test the service, pack the version in `Directory.Build.props`,
inspect metadata and licensing, and execute a fresh package-only consumer. The release directory
contains the package, matching notes, source/package evidence and SHA-256 checksums. Local artifacts
do not imply a public package or a working Google deployment.

The approved trusted-publisher tuple is NuGet account `CrosswiredStudios`, GitHub repository
`CrosswiredStudios/CSweet.ConnectionService`, workflow `publish.yml`, environment `release`, and
only package ID `CSweet.ConnectionService.Protocol` (create/push for first publication). Before
dispatch, independently confirm that policy exists for the authenticated NuGet owner. No permanent
NuGet API key is required or stored.

The `release` environment requires owner `CrosswiredStudios` review, disables administrator bypass,
and permits only branch `main`, with no tag rule. Self-review is permitted for the sole owner.
After source review and passing CI, dispatch `publish.yml` on the reviewed main revision with
`publish` selected. The default dispatch only verifies. Only the publish job has `id-token: write`.

Verification uploads an immutable release artifact. Publishing downloads that exact artifact ID,
checks its closed file list, all checksums, exact package ID/version, clean source revision and
NuGet repository metadata, then uses `NuGet/login@v1` for a temporary credential. An existing NuGet
version fails instead of being silently skipped. Check an uncertain result before retrying.
The workflow creates no tag or GitHub release.

Confirm nuget.org indexing and a clean consumer restore before updating downstream pins or merging
host changes that depend on this package. Publishing grants no provider authority and deploys no
service, DNS record, OAuth credentials or account data.
