namespace CookieStealer.Utilities;

public class Log
{
    public Log()
    {
        if (!Directory.Exists("logs"))
        {
            Directory.CreateDirectory("logs");
        }
    }
    
    
    
}