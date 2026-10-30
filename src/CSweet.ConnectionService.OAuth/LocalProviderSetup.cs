using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CSweet.ConnectionService.Protocol;
using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record LocalSetupCommand(string Action, string ServiceOrigin,
    LocalCredentialSetup? CredentialImport, LocalPackageSetup? PackageApproval)
{
    public static LocalSetupCommand Parse(byte[] bytes)
    {
        if (bytes.Length > 65536) throw new ArgumentException("Command too large.");
        using var document = JsonDocument.Parse(bytes);
        RegistryService.CheckDuplicates(document.RootElement);
        var command = document.RootElement.Deserialize<LocalSetupCommand>(new JsonSerializerOptions(DeploymentProofCodec.Json) { RespectNullableAnnotations = true, RespectRequiredConstructorParameters = true }) ?? throw new ArgumentException("Missing command.");
        if (command.Action == "import-credentials" ? command.CredentialImport is null || command.PackageApproval is not null :
            command.Action == "approve-package" ? command.PackageApproval is null || command.CredentialImport is not null : true)
            throw new ArgumentException("Choose one typed local operation.");
        return command;
    }
}
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record LocalCredentialSetup(string ProfileId, string Format, string CredentialFile, long ExpectedProfileRevision, long ExpectedSecretVersion);
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record LocalPackageSetup(string PackageDigest, string ManifestSha256, string ManifestFile,
    string ProfileId, long ExpectedProfileRevision, string RepositoryUrl, string SourceCommit);
public sealed record LocalSetupResult(string Action, string ProfileId, long ProfileRevision, long? SecretVersion, string? PackageDigest, bool Changed);

public static class LocalSetupFiles
{
    public static async Task<byte[]> Read(string path, int maximum, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(path) || Path.GetFullPath(path) != path) throw new ArgumentException("Use an absolute file path.");
        var info = new FileInfo(path);
        if (info.LinkTarget is not null || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new ArgumentException("Use a regular local file.");
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(file.SafeFileHandle);
            if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new ArgumentException("Restrict local input file permissions.");
        }
        if (file.Length > maximum) throw new ArgumentException("Input exceeds limit.");
        using var output = new MemoryStream(); var buffer = new byte[4096]; int read;
        while ((read = await file.ReadAsync(buffer, ct)) > 0)
        {
            if (output.Length + read > maximum) throw new ArgumentException("Input exceeds limit.");
            output.Write(buffer, 0, read);
        }
        info.Refresh();
        if (info.LinkTarget is not null) throw new ArgumentException("Input changed while reading.");
        return output.ToArray();
    }
}

/// <summary>Host-local OS authority only. Not registered as an HTTP endpoint and never grants remote authority.</summary>
public sealed class LocalProviderSetup(ConnectionStore db, RegistryService registry, ServiceOptions options,
    IEnumerable<IOAuthCredentialDocumentReader> readers)
{
    public async Task<LocalSetupResult> Execute(LocalSetupCommand command, CancellationToken ct)
    {
        // Validate even direct in-process callers using the same closed input contract.
        command = LocalSetupCommand.Parse(JsonSerializer.SerializeToUtf8Bytes(command, DeploymentProofCodec.Json));
        if (command.ServiceOrigin != options.PublicOrigin) throw new ArgumentException("Wrong service origin.");
        var actor = "local-os:" + Environment.UserName;
        if (command.CredentialImport is { } import)
        {
            if (import.ExpectedProfileRevision < 0 || import.ExpectedSecretVersion < 0 ||
                (import.ExpectedProfileRevision == 0) != (import.ExpectedSecretVersion == 0)) throw new ArgumentException("Review both profile versions.");
            var reader = readers.SingleOrDefault(x => x.Format == import.Format) ?? throw new ArgumentException("Unknown credential format.");
            var bytes = await LocalSetupFiles.Read(import.CredentialFile, 65536, ct);
            try
            {
                using var document = JsonDocument.Parse(bytes); RegistryService.CheckDuplicates(document.RootElement);
                var request = reader.Read(import.ProfileId, document.RootElement, options.Callback(import.ProfileId));
                // SQLite serializes writers before the read/check/write sequence. Registry saves and
                // its content-free audit event remain inside this outer transaction.
                await using var tx = await db.Database.BeginTransactionAsync(ct);
                var current = await db.Profiles.SingleOrDefaultAsync(x => x.Id == import.ProfileId, ct);
                if (current is null ? import.ExpectedProfileRevision != 0 || import.ExpectedSecretVersion != 0 :
                    current.Revision != import.ExpectedProfileRevision || current.SecretVersion != import.ExpectedSecretVersion)
                    throw new InvalidOperationException("Stale profile versions.");
                await registry.Configure(actor, request, ct);
                var saved = await db.Profiles.SingleAsync(x => x.Id == import.ProfileId, ct);
                await tx.CommitAsync(ct);
                return new(command.Action, saved.Id, saved.Revision, saved.SecretVersion, null, true);
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
        var approval = command.PackageApproval!;
        if (approval.ExpectedProfileRevision < 1 || approval.SourceCommit != approval.SourceCommit.ToLowerInvariant())
            throw new ArgumentException("Review the active profile and canonical commit.");
        var manifestBytes = await LocalSetupFiles.Read(approval.ManifestFile, 750000, ct);
        var manifest = new UTF8Encoding(false, true).GetString(manifestBytes);
        if (DeploymentProofCodec.Hash(manifestBytes) != approval.ManifestSha256) throw new ArgumentException("Manifest mismatch.");
        var identity = JsonSerializer.SerializeToUtf8Bytes(new { format = "connector-declarations.v1", repository = approval.RepositoryUrl,
            commit = approval.SourceCommit, manifest = approval.ManifestSha256 });
        if (DeploymentProofCodec.Hash(identity) != approval.PackageDigest) throw new ArgumentException("Connector declaration digest mismatch.");
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var exists = await db.Packages.AnyAsync(x => x.Digest == approval.PackageDigest, ct);
        await registry.Approve(actor, new(approval.PackageDigest, approval.ManifestSha256, manifest, approval.ProfileId,
            approval.ExpectedProfileRevision, approval.RepositoryUrl, approval.SourceCommit), ct);
        await transaction.CommitAsync(ct);
        return new(command.Action, approval.ProfileId, approval.ExpectedProfileRevision, null, approval.PackageDigest, !exists);
    }
}
