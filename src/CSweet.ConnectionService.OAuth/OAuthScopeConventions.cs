namespace CSweet.ConnectionService;

/// <summary>Statically trusted protocol differences; never supplied as executable plugin code.</summary>
public interface IOAuthScopeConvention
{
    bool Matches(ProviderProfile profile);
    string Canonical(string scope);
    int AuthorizationOrder(string scope);
}

public sealed class OAuthScopeConventions(IEnumerable<IOAuthScopeConvention> conventions)
{
    private IOAuthScopeConvention? For(ProviderProfile profile)
    {
        var matching = conventions.Where(x => x.Matches(profile)).Take(2).ToArray();
        if (matching.Length > 1) throw new InvalidOperationException("Ambiguous provider conventions.");
        return matching.SingleOrDefault();
    }
    public HashSet<string> Canonical(ProviderProfile profile, IEnumerable<string> scopes)
    {
        var adapter = For(profile);
        return scopes.Select(x => adapter?.Canonical(x) ?? x).ToHashSet(StringComparer.Ordinal);
    }
    public string AuthorizationValue(ProviderProfile profile, IEnumerable<string> scopes)
    {
        var adapter = For(profile);
        return string.Join(' ', scopes.OrderBy(x => adapter?.AuthorizationOrder(x) ?? 0).ThenBy(x => x, StringComparer.Ordinal));
    }
}
