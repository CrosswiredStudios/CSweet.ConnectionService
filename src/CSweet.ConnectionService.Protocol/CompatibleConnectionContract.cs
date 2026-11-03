using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CSweet.ConnectionService.Protocol;

/// <summary>Conservative, provider-neutral compatibility for an existing consent. Package identity,
/// provider registration and approval remain independent checks at each trust boundary.</summary>
public static class CompatibleConnectionContract
{
    public static string Require(JsonElement source, JsonElement target, IReadOnlyList<string> grantedScopeSets)
    {
        Check(source); Check(target);
        if (grantedScopeSets.Count is < 1 or > 32 || grantedScopeSets.Distinct(StringComparer.Ordinal).Count()!=grantedScopeSets.Count ||
            grantedScopeSets.Any(x=>string.IsNullOrWhiteSpace(x) || x.Length>128 || x.Any(char.IsControl))) throw Denied();
        JsonElement Unchanged(JsonElement manifest)=>JsonSerializer.SerializeToElement(manifest.EnumerateObject()
            .Where(p=>p.Name is not ("version" or "providerOperations")).ToDictionary(p=>p.Name,p=>p.Value,StringComparer.Ordinal));
        if(Canonical(Unchanged(source))!=Canonical(Unchanged(target)))throw Denied();
        if(source.GetProperty("kind").GetString()!="connector" || source.GetProperty("accounts").ValueKind!=JsonValueKind.Object ||
            source.GetProperty("connections").GetArrayLength()!=1 || source.GetProperty("webAccess").GetProperty("mode").GetString()!="None") throw Denied();
        var sets=source.GetProperty("connections")[0].GetProperty("scopeSets").EnumerateArray().ToArray();
        if(grantedScopeSets.Any(id=>sets.Count(s=>s.GetProperty("id").GetString()==id)!=1) ||
            sets.Where(s=>s.TryGetProperty("required",out var required) && required.ValueKind==JsonValueKind.True)
                .Any(s=>!grantedScopeSets.Contains(s.GetProperty("id").GetString()!,StringComparer.Ordinal))) throw Denied();
        string[] Effective(JsonElement manifest)=>manifest.GetProperty("providerOperations").EnumerateArray()
            .Where(op=>op.TryGetProperty("http",out var http) && http.ValueKind==JsonValueKind.Object &&
                http.GetProperty("scopeSets").EnumerateArray().All(s=>grantedScopeSets.Contains(s.GetString()!,StringComparer.Ordinal)))
            .Select(Canonical).Order(StringComparer.Ordinal).ToArray();
        var before=Effective(source); var after=Effective(target);
        if(before.Length==0 || !before.SequenceEqual(after,StringComparer.Ordinal)) throw Denied();
        // Declaration array order and unknown semantic changes are rejected; operation collection order is immaterial.
        var contract=JsonSerializer.SerializeToElement(new { Accounts=source.GetProperty("accounts"),Connections=source.GetProperty("connections"),
            Provides=source.GetProperty("provides"),Requires=source.GetProperty("requires"),EffectiveOperations=before,
            GrantedScopeSets=grantedScopeSets.Order(StringComparer.Ordinal).ToArray() });
        return Hash(contract);
    }
    public static string Hash(JsonElement value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(value))));
    public static string Canonical(JsonElement value)
    {
        using var stream=new MemoryStream(); using(var writer=new Utf8JsonWriter(stream)) Write(writer,value);
        return Encoding.UTF8.GetString(stream.ToArray());
    }
    private static void Write(Utf8JsonWriter writer,JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object)
        { writer.WriteStartObject(); foreach(var p in value.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal))
            {writer.WritePropertyName(p.Name);Write(writer,p.Value);} writer.WriteEndObject(); }
        else if(value.ValueKind==JsonValueKind.Array)
        {writer.WriteStartArray();foreach(var item in value.EnumerateArray())Write(writer,item);writer.WriteEndArray();}
        else value.WriteTo(writer);
    }
    private static void Check(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object)
        {var names=new HashSet<string>(StringComparer.Ordinal);foreach(var property in value.EnumerateObject())
            {if(!names.Add(property.Name))throw Denied();Check(property.Value);}}
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Check(item);
    }
    private static UnauthorizedAccessException Denied()=>new("The reviewed contracts do not preserve this consent's effective authority.");
}
