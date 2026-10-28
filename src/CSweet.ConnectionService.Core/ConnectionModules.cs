using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace CSweet.ConnectionService.Core;

/// <summary>Statically trusted platform features. Never populated by customer plugin executables.</summary>
public interface IConnectionModule
{
    string Kind { get; }
    string Protocol { get; }
    void MapEndpoints(IEndpointRouteBuilder endpoints);
}

public static class ConnectionModules
{
    public static void MapConnectionModules(this IEndpointRouteBuilder endpoints)
    {
        var modules = endpoints.ServiceProvider.GetServices<IConnectionModule>().ToArray();
        if (modules.Length == 0 || modules.Any(x => string.IsNullOrWhiteSpace(x.Kind)) ||
            modules.Select(x => x.Kind).Distinct(StringComparer.Ordinal).Count() != modules.Length)
            throw new InvalidOperationException("Connection modules must have unique stable identities.");
        endpoints.MapGet("/features", () => modules.Select(x => new { kind = x.Kind, protocol = x.Protocol }));
        foreach (var module in modules) module.MapEndpoints(endpoints);
    }
}
