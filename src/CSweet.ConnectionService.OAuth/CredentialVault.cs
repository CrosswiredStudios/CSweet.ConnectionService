using Microsoft.AspNetCore.DataProtection;

namespace CSweet.ConnectionService;

/// <summary>Keys are certificate-encrypted in persistent restricted storage; purposes isolate records.</summary>
public sealed class CredentialVault(IDataProtectionProvider protection)
{
    public string Seal(string purpose, string value) => protection.CreateProtector("CSweet.ManagedConnection.v1", purpose).Protect(value);
    public string Open(string purpose, string value) => protection.CreateProtector("CSweet.ManagedConnection.v1", purpose).Unprotect(value);
}
