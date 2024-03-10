using System.Diagnostics;
using System.Text;
using CookieLocker.Utilities;
using Spectre.Console;

namespace CookieLocker;

internal static class Program
{
    private const string FilesPath = "files";
    private const string InputFile = "files\\file.txt";
    public const string EncryptedFile = "files\\file.encrypted";
    public const string DecryptedFile = "files\\file.decrypted";
    private const string KeyPath = "files\\key.bin";
    private const string HashPath = "files\\hash";
    
    private const string ArgChangePassword = "change-password";
    private const string ArgDecrypt = "decrypt";
    private const string ArgRegenerateKey = "regenerate-key";
    
    public static Dictionary<string,BrowserInfo> Browsers = null!; 
    
    public static void Main(string[] args)
    {
        Console.Clear();
        
        
        Browsers = new BrowserData().Browsers;
        Directory.CreateDirectory(FilesPath);
        
        
        if (!Path.Exists(EncryptedFile))
        {
            FirstEncryptionProcess(Browsers);
            return;
        }
        
        var encryptionMethod = Tools.IdentifyEncryptionMethod(EncryptedFile);

        string password = null!;
        if (encryptionMethod == "AES") password = Tools.PasswordPrompt(HashPath);
        
        YubiKeyEncryption yubi = null!;
        
        switch (args.Length)
        {
            case 0:
                string browserName;
                
                if (encryptionMethod == "AES")
                {
                    browserName = AesEncryption.DecryptFile(EncryptedFile, DecryptedFile, Browsers, KeyPath, password);
                }
                else
                {
                    yubi = new YubiKeyEncryption();
                    browserName = yubi.DecryptFile();
                }

                if (browserName == "") break;
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = Browsers[browserName].ProcessName,
                        UseShellExecute = true,
                    }
                };
                process.Start();
                AnsiConsole.MarkupLine("Browser started successfully.");
                AnsiConsole.MarkupLine("Do [red]NOT[/] close this window.");
                process.WaitForExit();
                AnsiConsole.MarkupLine("Browser has closed.");
                Thread.Sleep(500);
                if (encryptionMethod == "AES")
                {
                    AesEncryption.ReEncryptFile(Browsers, DecryptedFile, EncryptedFile, KeyPath, password);
                }
                else
                {
                    yubi.EncryptFile();
                }
                break;
            
            case 1 when args[0] == ArgChangePassword && encryptionMethod == "AES":
                var newPassword = Tools.NewPasswordPrompt();
                var encryptedKey = File.ReadAllBytes(KeyPath);
                var key = AesEncryption.DecryptKey(encryptedKey, password);
                var newEncryptedKey = AesEncryption.EncryptKey(key, newPassword);
                File.WriteAllBytes(KeyPath, newEncryptedKey);
                File.WriteAllText(HashPath, AesEncryption.HashPassword(newPassword));
                AnsiConsole.MarkupLine("[green]Password changed successfully.[/]");
                break;
            
            case 1 when args[0] == ArgDecrypt && encryptionMethod == "AES":
                AesEncryption.DecryptFile(EncryptedFile, DecryptedFile, Browsers, KeyPath, password);
                File.Delete(EncryptedFile);
                File.Delete(HashPath);
                File.Delete(KeyPath);
                AnsiConsole.MarkupLine("[green]File decrypted successfully.[/]");
                break;
            
            case 1 when args[0] == ArgDecrypt && encryptionMethod == "YubiKey":
                yubi = new YubiKeyEncryption();
                yubi.DecryptFile();
                File.Delete(EncryptedFile);
                AnsiConsole.MarkupLine("[green]File decrypted successfully.[/]");
                break;
                
            
            case 1 when args[0] == ArgRegenerateKey && encryptionMethod == "AES":
                var newKey = AesEncryption.GenerateEncryptionKey();
                var modifiedEncryptedKey = AesEncryption.EncryptKey(newKey, password);
                File.WriteAllBytes(KeyPath, modifiedEncryptedKey);
                AesEncryption.ReEncryptFile(Browsers, DecryptedFile, EncryptedFile, KeyPath, password);
                AnsiConsole.MarkupLine("[green]Key regenerated successfully.[/]");
                break;
            
            default:
                AnsiConsole.MarkupLine("[red]Too many arguments.[/]");
                break;
        }
        
    }

    
    
    
    
    
    private static void FirstEncryptionProcess(Dictionary<string,BrowserInfo> browsers)
    {
        if (!AnsiConsole.Confirm("Your browser cookies will be encrypted. Do you want to continue?"))
        {
            AnsiConsole.MarkupLine("Exiting...");
            Environment.Exit(0);
        }
        
        AnsiConsole.Clear();
        
        var browserNames = browsers.Keys.ToList();

        var chosenBrowserName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Choose a browser:")
                .PageSize(10)
                .AddChoiceGroup("Browsers", browserNames)
                .AddChoiceGroup("Other", new[] {"Custom", "Cancel"})
        );
        string chosenProfileName = null!;
        string? inputFilePath = null;
        
        switch (chosenBrowserName)
        {
            case "Custom":
                chosenBrowserName = null!;
                do
                {
                    inputFilePath = AnsiConsole.Ask<string>("Enter the path to the Cookies file: ");
                    inputFilePath = inputFilePath.Trim('\"').Replace(@"\", @"\\");
                    if (!File.Exists(inputFilePath))
                    {
                        AnsiConsole.MarkupLine("File does not exist. Please try again.");
                    }
                } while (!File.Exists(inputFilePath));
                break;
            
            case "Cancel":
                Environment.Exit(0);
                break;
            
            default:
                var chosenBrowser = browsers[chosenBrowserName];
                if (chosenBrowser.ProfilesPossible && chosenBrowser.ProfileList.Count > 1)
                {
                    var profileNames = chosenBrowser.ProfileList.Select(profile => Path.GetFileName(Tools.GetParentDirectory(profile, 2))).ToList();
                    profileNames.Insert(0, "Default");
                    chosenProfileName = AnsiConsole.Prompt(
                        new SelectionPrompt<string>()
                            .Title("Choose a profile:")
                            .PageSize(10)
                            .AddChoices(profileNames.Select(p => p.ToString()).ToList()));

                    Console.WriteLine($"[{chosenBrowserName} - {chosenProfileName}]\n");
                    inputFilePath = chosenProfileName == "Default"
                        ? chosenBrowser.PathToCookiesFile
                        : chosenBrowser.ProfileList[profileNames.IndexOf(chosenProfileName) - 1];
                }
                else
                {
                    chosenProfileName = "Default";
                    inputFilePath = browsers[chosenBrowserName].PathToCookiesFile;
                }
                break;
                
        }

        var encryptionMethod = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Choose encryption method:")
                .PageSize(10)
                .AddChoices("Local AES Encryption", "YubiKey Encryption")
        );

        switch (encryptionMethod)
        {
            case "Local AES Encryption":
                AesFileEncryption(chosenBrowserName, chosenProfileName, inputFilePath, browsers);
                break;
            case "YubiKey Encryption":
                var yubi = new YubiKeyEncryption();
                yubi.EncryptFile(inputFilePath, chosenBrowserName, chosenProfileName);
                break;
        }
    }


    private static void AesFileEncryption(
        string? chosenBrowserName,
        string chosenProfileName,
        string? inputFilePath,
        IReadOnlyDictionary<string, BrowserInfo> browsers)
    {
        var password = Tools.NewPasswordPrompt();
        var encryptedKey= AesEncryption.EncryptKey(AesEncryption.GenerateEncryptionKey(), password);
        var passwordHash = AesEncryption.HashPassword(password);
        
        File.WriteAllBytes(KeyPath, encryptedKey);
        File.WriteAllText(HashPath, passwordHash);

        if (chosenBrowserName != null)
        {
            Tools.ProcessManager(browsers[chosenBrowserName], chosenBrowserName);
        }
        AesEncryption.EncryptFile(inputFilePath, EncryptedFile, KeyPath, password, chosenBrowserName, chosenProfileName);
    }
    
}