using CSweet.ConnectionService;
using CSweet.ConnectionService.Core;
using CSweet.ConnectionService.OAuth.Google;

var builder = WebApplication.CreateBuilder(args);
builder.AddManagedOAuth();
builder.Services.AddGoogleOAuthSupport();
var app = builder.Build();
await app.InitializeManagedOAuth(args);
if (args.Contains("--initialize-store", StringComparer.Ordinal) || args.Contains("--migrate-store", StringComparer.Ordinal)) return;
app.UseManagedOAuth();
app.MapConnectionModules();
app.MapOAuthCredentialImports();
app.Run();
public partial class Program;
