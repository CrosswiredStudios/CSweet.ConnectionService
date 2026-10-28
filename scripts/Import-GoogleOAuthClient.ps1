[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$ServiceOrigin,
    [Parameter(Mandatory)][string]$ProfileId,
    [Parameter(Mandatory)][string]$CredentialFile
)
$ErrorActionPreference = 'Stop'
if ($ServiceOrigin.Scheme -ne 'https' -or $ServiceOrigin.UserInfo -or $ServiceOrigin.Query -or $ServiceOrigin.Fragment -or $ServiceOrigin.AbsolutePath -ne '/') {
    throw 'Use the exact trusted HTTPS service origin.'
}
$source = Get-Item -LiteralPath $CredentialFile
if ($source.Length -gt 65536) { throw 'Credential document exceeds the import limit.' }
$operatorToken = Read-Host 'Operator access token for this service (input is hidden)' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($operatorToken)
try {
    $bearer = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $document = Get-Content -LiteralPath $source.FullName -Raw | ConvertFrom-Json
    $body = @{ profileId = $ProfileId; document = $document } | ConvertTo-Json -Depth 12 -Compress
    try {
        $result = Invoke-RestMethod -Method Post -Uri ($ServiceOrigin.AbsoluteUri.TrimEnd('/') + '/operator/credential-imports/google-web-client') `
            -Headers @{Authorization = 'Bearer ' + $bearer} -ContentType 'application/json' -Body $body
        [pscustomobject]@{ ProfileId = $result.profileId; CallbackUri = $result.callbackUri; PublicRevision = $result.publicRevision }
    } catch { throw 'Credential import was not accepted. Check operator authority and the exact registered service callback. Secret values were not displayed.' }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $bearer = $null; $body = $null; $document = $null; $operatorToken.Dispose()
}
