using System.Diagnostics;
using CookieLocker.Utilities;
using Spectre.Console;

namespace CookieLocker;

internal static class Program
{
    private const string filesPath = "files";
    private const string InputFile = "files\\file.txt";
    private const string EncryptedFile = "files\\file.encrypted";
    private const string DecryptedFile = "files\\file.decrypted";
    private const string KeyPath = "files\\key.bin";
    private const string hashPath = "files\\hash";
    
    public static void Main(string[] args)
    {
        Console.Clear();
        
        var browsers = new BrowserData().Browsers;
        
        Directory.CreateDirectory(filesPath);
        
        if (Directory.GetFiles(filesPath).Length != 0)
        {
            // Decrypt, launch and encrypt
            var password = PasswordPrompt();
            var browserName = AesEncryption.DecryptFile(EncryptedFile, DecryptedFile, browsers, KeyPath, password);
            // if (args[0] == "decrypt")
            // {
            //     Environment.Exit(0);
            // }
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = browsers[browserName].ProcessName,
                    UseShellExecute = true,
                }
            };
            process.Start();
            process.WaitForExit();
            Console.WriteLine("Browser Stopped");
            Thread.Sleep(2*1000);
            AesEncryption.ReEncryptFile(browsers, DecryptedFile, EncryptedFile, KeyPath, password);
            
        }
        else
        {
            EncryptionProcess(browsers);
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
        
        // Console.WriteLine(inputFilePath);

        string password = null!;
        string repeatPassword = null!;
        do
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter password: ")
                    .Secret());

            repeatPassword = AnsiConsole.Prompt(
                new TextPrompt<string>("Repeat password: ")
                    .Secret());

            if (password != repeatPassword)
            {
                AnsiConsole.MarkupLine("Passwords do not match. Try again.");
            }
        } while (password != repeatPassword);
        
        var encryptedKey= AesEncryption.EncryptKey(AesEncryption.GenerateEncryptionKey(), password);
        File.WriteAllBytes(KeyPath, encryptedKey);
        
        var passwordHash = AesEncryption.HashPassword(password);
        File.WriteAllText(hashPath, passwordHash);

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
            access = AesEncryption.VerifyPassword(password, hashPath);
            if (!access)
            {
                AnsiConsole.MarkupLine("Incorrect password. Try again.");
            }
        } while (!access);

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