using System.Diagnostics;
using CookieLocker.Utilities;
using Spectre.Console;

namespace CookieLocker;

internal static class Program
{
    private const string FilesPath = "files";
    private const string InputFile = "files\\file.txt";
    private const string EncryptedFile = "files\\file.encrypted";
    private const string DecryptedFile = "files\\file.decrypted";
    private const string KeyPath = "files\\key.bin";
    private const string HashPath = "files\\hash";
    
    private const string ArgChangePassword = "change-password";
    private const string ArgDecrypt = "decrypt";
    private const string ArgRegenerateKey = "regenerate-key";
    
    public static void Main(string[] args)
    {
        Console.Clear();
        
        // TEMP

        var yubi = new YubiKeyEncryption();
        
        // var encryptedBytes = yubi.EncryptFile(InputFile);
        // File.WriteAllBytes(EncryptedFile, encryptedBytes);
        var decryptedBytes = yubi.DecryptFile(EncryptedFile);
        File.WriteAllBytes(DecryptedFile, decryptedBytes);
        
        
        Environment.Exit(0);
        // TEMP
        
        
        
        var browsers = new BrowserData().Browsers;
        Directory.CreateDirectory(FilesPath);
        
        
        
        if (Directory.GetFiles(FilesPath).Length == 0)
        {
            EncryptionProcess(browsers);
            return;
        }
        
        var password = PasswordPrompt();
        
        switch (args.Length)
        {
            case 0:
                var browserName = AesEncryption.DecryptFile(EncryptedFile, DecryptedFile, browsers, KeyPath, password);
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = browsers[browserName].ProcessName,
                        UseShellExecute = true,
                    }
                };
                process.Start();
                AnsiConsole.MarkupLine("Browser started successfully.");
                AnsiConsole.MarkupLine("Do [red]NOT[/] close this window.");
                process.WaitForExit();
                AnsiConsole.MarkupLine("Browser has closed.");
                Thread.Sleep(500);
                AesEncryption.ReEncryptFile(browsers, DecryptedFile, EncryptedFile, KeyPath, password);
                break;
            
            case 1 when args[0] == ArgChangePassword:
                var newPassword = NewPasswordPrompt();
                var encryptedKey = File.ReadAllBytes(KeyPath);
                var key = AesEncryption.DecryptKey(encryptedKey, password);
                var newEncryptedKey = AesEncryption.EncryptKey(key, newPassword);
                File.WriteAllBytes(KeyPath, newEncryptedKey);
                File.WriteAllText(HashPath, AesEncryption.HashPassword(newPassword));
                AnsiConsole.MarkupLine("[green]Password changed successfully.[/]");
                break;
            
            case 1 when args[0] == ArgDecrypt:
                AesEncryption.DecryptFile(EncryptedFile, DecryptedFile, browsers, KeyPath, password);
                File.Delete(EncryptedFile);
                File.Delete(HashPath);
                File.Delete(KeyPath);
                AnsiConsole.MarkupLine("[green]File decrypted successfully.[/]");
                break;
            
            case 1 when args[0] == ArgRegenerateKey:
                var newKey = AesEncryption.GenerateEncryptionKey();
                var modifiedEncryptedKey = AesEncryption.EncryptKey(newKey, password);
                File.WriteAllBytes(KeyPath, modifiedEncryptedKey);
                AesEncryption.ReEncryptFile(browsers, DecryptedFile, EncryptedFile, KeyPath, password);
                AnsiConsole.MarkupLine("[green]Key regenerated successfully.[/]");
                break;
            
            default:
                AnsiConsole.MarkupLine("[red]Invalid arguments.[/]");
                break;
        }
        
    }

    
    
    
    
    
    private static void EncryptionProcess(Dictionary<string,BrowserInfo> browsers)
    {
        if (!AnsiConsole.Confirm("Your browser cookies will be encrypted. Do you want to continue?"))
        {
            AnsiConsole.MarkupLine("Exiting...");
            Environment.Exit(0);
        }
        
        var browserNames = browsers.Keys.ToList();

        var chosenBrowserName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Choose a browser:")
                .PageSize(10)
                .AddChoiceGroup("Browsers", browserNames)
                .AddChoiceGroup("Other", new[] {"Custom", "Cancel"})
        );
        string chosenProfileName = null!;
        
        if (chosenBrowserName == "Cancel")
        {
            Environment.Exit(0);
        }
        
        string? inputFilePath;
        if (chosenBrowserName == "Custom")
        {
            chosenBrowserName = null;
            do
            {
                inputFilePath = AnsiConsole.Ask<string>("Enter the path to the Cookies file: ");
                inputFilePath = inputFilePath.Trim('\"').Replace(@"\", @"\\");
                if (!File.Exists(inputFilePath))
                {
                    AnsiConsole.MarkupLine("File does not exist. Please try again.");
                }
            } while (!File.Exists(inputFilePath));
            
        }
        else
        {
            var chosenBrowser = browsers[chosenBrowserName];
            if (chosenBrowser.ProfilesPossible && chosenBrowser.ProfileList.Count > 1)
            {
                var profileNames = chosenBrowser.ProfileList.Select(profile => Path.GetFileName(GetParentDirectory(profile, 2))).ToList();
                profileNames.Insert(0, "Default");
                chosenProfileName = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("Choose a profile:")
                        .PageSize(10)
                        .AddChoices(profileNames.Select(p => p.ToString()).ToList()));

                Console.WriteLine($"You chose {chosenBrowserName} - {chosenProfileName}");
                inputFilePath = chosenProfileName == "Default"
                    ? chosenBrowser.PathToCookiesFile
                    : chosenBrowser.ProfileList[profileNames.IndexOf(chosenProfileName) - 1];
            }
            else
            {
                chosenProfileName = "Default";
                inputFilePath = browsers[chosenBrowserName].PathToCookiesFile;
            }
        }

        var password = NewPasswordPrompt();
        
        var encryptedKey= AesEncryption.EncryptKey(AesEncryption.GenerateEncryptionKey(), password);
        File.WriteAllBytes(KeyPath, encryptedKey);
        
        var passwordHash = AesEncryption.HashPassword(password);
        File.WriteAllText(HashPath, passwordHash);

        if (chosenBrowserName != null)
        {
            Tools.ProcessManager(browsers[chosenBrowserName], chosenBrowserName);
        }
        AesEncryption.EncryptFile(inputFilePath, EncryptedFile, KeyPath, password, chosenBrowserName, chosenProfileName);
        
        File.Delete(inputFilePath);
    }
    
    
    private static string PasswordPrompt()
    {
        var access = false;
        string password = null!;
        do
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter password: ")
                    .Secret());
            access = AesEncryption.VerifyPassword(password, HashPath);
            if (!access)
            {
                AnsiConsole.MarkupLine("[yellow]Incorrect password. Try again.[/]");
            }
        } while (!access);
        
        AnsiConsole.MarkupLine("[green]Correct password.[/]");

        return password;
    }

    private static string NewPasswordPrompt()
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

    private static string GetParentDirectory(string path, int levels)
    {
        for (var i = 0; i < levels; i++)
        {
            path = Directory.GetParent(path)?.FullName;
        }

        return path;
    }
}