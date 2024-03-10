using System.Security.Cryptography;
using System.Text;

namespace CookieLocker.Utilities;

public static class AesEncryption
{
    public static byte[] GenerateEncryptionKey()
    {
        var key = new byte[16]; // 128 bit - 16 bytes / 192 bit - 24 bytes / 256 bit - 32 bytes
        RandomNumberGenerator.Fill(key);
        return key;
    }

    public static byte[] EncryptKey(byte[] key, string? password)
    {
        var salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        var passwordKey = pbkdf2.GetBytes(32);

        using var aes = Aes.Create();
        aes.Key = passwordKey;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var encryptedKey = encryptor.TransformFinalBlock(key, 0, key.Length);

        var encryptedKeyWithIvAndSalt = new byte[aes.IV.Length + salt.Length + encryptedKey.Length];
        Buffer.BlockCopy(aes.IV, 0, encryptedKeyWithIvAndSalt, 0, aes.IV.Length);
        Buffer.BlockCopy(salt, 0, encryptedKeyWithIvAndSalt, aes.IV.Length, salt.Length);
        Buffer.BlockCopy(encryptedKey, 0, encryptedKeyWithIvAndSalt, aes.IV.Length + salt.Length, encryptedKey.Length);

        return encryptedKeyWithIvAndSalt;
    }

    public static string HashPassword(string password)
    {
        var salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);

        var hashWithSalt = new byte[salt.Length + hash.Length];
        Buffer.BlockCopy(salt, 0, hashWithSalt, 0, salt.Length);
        Buffer.BlockCopy(hash, 0, hashWithSalt, salt.Length, hash.Length);

        return Convert.ToBase64String(hashWithSalt);
    }

    public static bool VerifyPassword(string password, string storedHashPath)
    {
        var storedHash = File.ReadAllText(storedHashPath);
        var hashWithSalt = Convert.FromBase64String(storedHash);

        var salt = new byte[16];
        Buffer.BlockCopy(hashWithSalt, 0, salt, 0, salt.Length);

        var storedPasswordHash = new byte[hashWithSalt.Length - salt.Length];
        Buffer.BlockCopy(hashWithSalt, salt.Length, storedPasswordHash, 0, storedPasswordHash.Length);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        var passwordHash = pbkdf2.GetBytes(32);

        return passwordHash.SequenceEqual(storedPasswordHash);
    }

    public static byte[] DecryptKey(byte[] encryptedKeyWithIv, string password)
    {
        var iv = new byte[16];
        var salt = new byte[16];
        var encryptedKey = new byte[encryptedKeyWithIv.Length - 32];

        Buffer.BlockCopy(encryptedKeyWithIv, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(encryptedKeyWithIv, iv.Length, salt, 0, salt.Length);
        Buffer.BlockCopy(encryptedKeyWithIv, iv.Length + salt.Length, encryptedKey, 0, encryptedKey.Length);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        var passwordKey = pbkdf2.GetBytes(32);

        using var aes = Aes.Create();
        aes.Key = passwordKey;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedKey, 0, encryptedKey.Length);
    }

    public static void EncryptFile(
        string inputFilePath,
        string outputFilePath,
        string encryptedKeyPath,
        string password,
        string browserName,
        string profileName
        )
    {
        var prefix = Tools.PrefixGenerator(browserName, profileName);
        
        var encryptedKeyWithIv = File.ReadAllBytes(encryptedKeyPath);
        var key = DecryptKey(encryptedKeyWithIv, password);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        using var fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        fsOutput.Write(prefix, 0, prefix.Length);
        fsOutput.Write(aes.IV, 0, aes.IV.Length);

        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write);

        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0) cryptoStream.Write(buffer, 0, bytesRead);
        
        File.Delete(inputFilePath);
    }

    public static string DecryptFile(
        string inputFilePath,
        string defaultOutputPath,
        Dictionary<string,BrowserInfo> browsers,
        string encryptedKeyPath,
        string password)
    {
        var encryptedKeyWithIv = File.ReadAllBytes(encryptedKeyPath);
        var key = DecryptKey(encryptedKeyWithIv, password);

        using var fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);

        using var aes = Aes.Create();
        aes.Key = key;

        var prefixBytes = new byte[12];
        fsInput.Read(prefixBytes, 0, prefixBytes.Length);
        
        var iv = new byte[16];
        fsInput.Read(iv, 0, iv.Length);
        aes.IV = iv;

        var (outputFilePath, browserName) = Tools.ParsePrefix(prefixBytes);
        
        using var fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
        
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write);

        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0) cryptoStream.Write(buffer, 0, bytesRead);

        return browserName;
    }
    
    public static void ReEncryptFile(
        Dictionary<string,BrowserInfo> browsers,
        string defaultOutputPath,
        string encryptedFilePath,
        string encryptedKeyPath,
        string password
    )
    {
        var fsEncryptedInput = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read);
        
        var prefixBytes = new byte[12];
        fsEncryptedInput.Read(prefixBytes, 0, prefixBytes.Length);
        fsEncryptedInput.Dispose();

        var (inputFilePath, _) = Tools.ParsePrefix(prefixBytes);
        
        var encryptedKeyWithIv = File.ReadAllBytes(encryptedKeyPath);
        var key = DecryptKey(encryptedKeyWithIv, password);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        using var fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(encryptedFilePath, FileMode.Create, FileAccess.Write);

        fsOutput.Write(prefixBytes, 0, prefixBytes.Length);
        fsOutput.Write(aes.IV, 0, aes.IV.Length);

        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write);

        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0) cryptoStream.Write(buffer, 0, bytesRead);
        
        fsInput.Dispose();
        File.Delete(inputFilePath);
    }
    
    
    
}