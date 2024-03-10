using System.Diagnostics;
using System.Text;
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
    
    public static string PasswordPrompt(string hashPath)
    {
        var access = false;
        string password = null!;
        do
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter password: ")
                    .Secret());
            access = AesEncryption.VerifyPassword(password, hashPath);
            if (!access)
            {
                AnsiConsole.MarkupLine("[yellow]Incorrect password. Try again.[/]");
            }
        } while (!access);
        
        AnsiConsole.MarkupLine("[green]Correct password.[/]");

        return password;
    }

    public static string NewPasswordPrompt()
    {
        string password = null!;
        string repeatPassword = null!;
        do
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("New password: ")
                    .Secret());

            repeatPassword = AnsiConsole.Prompt(
                new TextPrompt<string>("Repeat password: ")
                    .Secret());

            if (password != repeatPassword)
            {
                AnsiConsole.MarkupLine("Passwords do not match. Try again.");
            }
        } while (password != repeatPassword);

        return password;
    }

    public static string GetParentDirectory(string path, int levels)
    {
        for (var i = 0; i < levels; i++)
        {
            path = Directory.GetParent(path)?.FullName;
        }

        return path;
    }
    
    public static (string, string) ParsePrefix(byte[] prefixBytes)
    {
        var cleanPrefixBytes = prefixBytes.Where(b => b != 0).ToArray();
        var prefix = Encoding.UTF8.GetString(cleanPrefixBytes);
        var browserInfo = prefix.Split(',').ToList();
        string filePath;
        if (browserInfo.Count == 1)
        {
            browserInfo.Add("");
            filePath = Program.DecryptedFile;
        }
        else
        {
            var browser = Program.Browsers[browserInfo[1]];
            var profileIndex = browserInfo[2][0];
            filePath = profileIndex == 'D'
                ? browser.PathToCookiesFile
                : browser.ProfileList[int.Parse(profileIndex.ToString()) - 2];
            Tools.ProcessManager(browser, browserInfo[0]);
        }
        
        return (filePath, browserInfo[1]);
    }

    public static byte[] PrefixGenerator(string? browserName, string profileName, bool isAes = true)
    {
        var prefix = new byte[12];
        var prefixString = isAes ? "A" : "Y";
        if (browserName != null)
        {
            var profileIndex = profileName == "Default"
                ? 'D'
                : profileName[^1];
            prefixString += $",{browserName},{profileIndex}";
        }
        var prefixBytes = Encoding.UTF8.GetBytes(prefixString);
        Array.Copy(prefixBytes, prefix, prefixBytes.Length);

        return prefix;
    }
    
    public static string IdentifyEncryptionMethod(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        var firstByte = fs.ReadByte();
        var firstChar = Encoding.UTF8.GetChars(new byte[] { (byte)firstByte })[0];
        
        return firstChar switch
        {
            'A' => "AES",
            'Y' => "YubiKey",
            _ => "Unknown"
        };
    }
    
    public static bool IsMoreRecent(string filePath)
    {
        var encryptedFileDate = File.GetLastWriteTime(Program.EncryptedFile);
        var originalFileDate = File.GetLastWriteTime(filePath);
        var timeDifference = originalFileDate - encryptedFileDate;
        
        return timeDifference.Seconds > 0;
    }
}