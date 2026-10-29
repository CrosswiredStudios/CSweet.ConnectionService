using Microsoft.EntityFrameworkCore;

namespace CSweet.ConnectionService;

/// <summary>Explicit additive SQLite upgrades. Never silently create or upgrade production storage on ordinary startup.</summary>
public static class ConnectionSchema
{
    public const string Version = "0.4.0";
    public static async Task Upgrade(ConnectionStore db, CancellationToken ct = default)
    {
        await db.Database.EnsureCreatedAsync(ct);
        await db.Database.OpenConnectionAsync(ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS OwnerBindings (Id TEXT NOT NULL PRIMARY KEY, ServiceOrigin TEXT NOT NULL, PublicKey TEXT NOT NULL, KeyId TEXT NOT NULL, Revision INTEGER NOT NULL, Revoked INTEGER NOT NULL)", ct);
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS OwnerGrants (BindingId TEXT NOT NULL, ActorId TEXT NOT NULL, TenantScope TEXT NOT NULL, CapabilitiesJson TEXT NOT NULL, Revision INTEGER NOT NULL, Revoked INTEGER NOT NULL, PRIMARY KEY (BindingId, ActorId))", ct);
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS OwnerNonces (BindingId TEXT NOT NULL, NonceHash TEXT NOT NULL, ExpiresAt INTEGER NOT NULL, PRIMARY KEY (BindingId, NonceHash))", ct);
        var columns = new Dictionary<string, Dictionary<string, string>>
        {
            ["Profiles"] = new() { ["RevocationGroup"] = "TEXT NULL" },
            ["Connections"] = new()
            {
                ["ProtectedInventory"] = "TEXT NOT NULL DEFAULT ''",
                ["SubjectHash"] = "TEXT NULL",
                ["InventoryVerifiedAt"] = "TEXT NULL",
                ["LeaseOwner"] = "TEXT NULL",
                ["LeaseUntil"] = "TEXT NULL",
                ["RevocationRequestedAt"] = "TEXT NULL",
                ["RevokedAt"] = "TEXT NULL",
                ["FailureCode"] = "TEXT NULL",
                ["RevocationAttempts"] = "INTEGER NOT NULL DEFAULT 0",
                ["NextRevocationAttempt"] = "INTEGER NOT NULL DEFAULT 0"
            }
        };
        foreach (var (table, additions) in columns)
        {
            var present = new HashSet<string>(StringComparer.Ordinal);
            await using (var command = db.Database.GetDbConnection().CreateCommand())
            {
                command.Transaction = transaction.GetDbTransaction(); command.CommandText = "PRAGMA table_info(\"" + table + "\")";
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) present.Add(reader.GetString(1));
            }
            foreach (var (column, type) in additions)
                if (!present.Contains(column))
                {
                    // All identifiers and types above are source-owned migration constants, never request data.
                    await using var command = db.Database.GetDbConnection().CreateCommand();
                    command.Transaction = transaction.GetDbTransaction();
                    command.CommandText = "ALTER TABLE \"" + table + "\" ADD COLUMN \"" + column + "\" " + type;
                    await command.ExecuteNonQueryAsync(ct);
                }
        }
        await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS \"__ConnectionSchema\" (\"Version\" TEXT NOT NULL PRIMARY KEY)", ct);
        await db.Database.ExecuteSqlInterpolatedAsync($"INSERT OR IGNORE INTO \"__ConnectionSchema\" (\"Version\") VALUES ({Version})", ct);
        await transaction.CommitAsync(ct);
    }
    public static async Task RequireCurrent(ConnectionStore db, CancellationToken ct = default)
    {
        await db.Database.OpenConnectionAsync(ct);
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='__ConnectionSchema'";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(ct)) == 0) throw new InvalidOperationException("Run --migrate-store before starting this service version.");
        command.CommandText = "SELECT COUNT(*) FROM \"__ConnectionSchema\" WHERE \"Version\" = '0.4.0'";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(ct)) != 1) throw new InvalidOperationException("The connection store schema needs an explicit upgrade.");
    }
}
