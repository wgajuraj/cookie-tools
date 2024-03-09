using System.Diagnostics;
using Spectre.Console;

namespace CookieLocker.Utilities;

public static class Tools
{
    public static void ProcessManager(BrowserInfo browser, string browserName)
    {
        var processes = Process.GetProcessesByName(browser.ProcessName);
        
        if (processes.Length == 0) return;
        
        if (!AnsiConsole.Confirm(
                $"Can't copy Cookies file because browser is currently running. Do you want to try to close {browserName}?"))
        {
            AnsiConsole.MarkupLine("Exiting...");
            Environment.Exit(0);
        }

        foreach (var process in processes)
        {
            process.CloseMainWindow();
            if (process.WaitForExit(3000)) continue;
            if (!AnsiConsole.Confirm($"Closing window failed. Do you want to kill {browserName}?"))
            {
                AnsiConsole.MarkupLine("Exiting...");
                Environment.Exit(0);
            }

            process.Kill();
            Thread.Sleep(500);
        }
    }
    
    public static void SecureDelete(IList<byte> data)
    {
        for (var i = 0; i < data.Count; i++) data[i] = 0;
    }
}