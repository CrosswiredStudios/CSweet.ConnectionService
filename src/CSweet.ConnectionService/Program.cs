using CSweet.ConnectionService;
using CSweet.ConnectionService.Core;
using CSweet.ConnectionService.OAuth.Google;

var builder = WebApplication.CreateBuilder(args);
builder.AddManagedOAuth();
builder.Services.AddGoogleOAuthSupport();
var app = builder.Build();
await app.InitializeManagedOAuth(args);
if (args.Contains("--initialize-store", StringComparer.Ordinal) || args.Contains("--migrate-store", StringComparer.Ordinal)) return;
if (args.Contains("--owner-admin", StringComparer.Ordinal))
{
    var index = Array.IndexOf(args, "--owner-admin");
    if (index + 1 >= args.Length) throw new InvalidOperationException("A protected local command file is required.");
    try
    {
        var file = new FileInfo(args[index + 1]); if (file.Length > 65536) throw new InvalidOperationException();
        await using var input = file.OpenRead();
        using var buffer = new MemoryStream(); var chunk = new byte[4096]; int count;
        while ((count = await input.ReadAsync(chunk)) > 0) { if (buffer.Length + count > 65536) throw new InvalidOperationException(); buffer.Write(chunk, 0, count); }
        var command = LocalOwnerCommand.Parse(buffer.ToArray());
        await using var scope = app.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<LocalOwnerAdministration>().Execute(command, default);
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result));
    }
    catch { Console.Error.WriteLine("Local owner administration failed. Check protected configuration and current revisions."); Environment.ExitCode = 1; }
    return;
}
app.UseManagedOAuth();
app.MapConnectionModules();
app.MapOAuthCredentialImports();
app.Run();
public partial class Program;
