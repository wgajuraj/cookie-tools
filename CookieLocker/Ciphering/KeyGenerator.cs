using System.Security.Cryptography;

namespace CookieLocker.Ciphering;

public class KeyGenerator
{
    public static byte[] GenerateKey()
    {
        using (var aes = new AesManaged())
        {
            aes.KeySize = 256;
            aes.GenerateKey();
            return aes.Key;
        }
    }
    
    public static byte[] GenerateIv()
    {
        using (var aes = new AesManaged())
        {
            aes.BlockSize = 128;
            aes.GenerateIV();
            return aes.IV;
        }
    }
    
    
    public static byte[] EncryptKey(byte[] key, string passphrase)
    {
        using (var aes = new AesManaged())
        {
            var salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);

            using (var ms = new MemoryStream())
            {
                // Write the salt to the start of the stream
                ms.Write(salt, 0, salt.Length);

                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(key, 0, key.Length);
                    cs.Close();
                }

                return ms.ToArray();
            }
        }
    }
    
    public static void WriteToFile(byte[] encryptedKey, string filePath)
    {
        File.WriteAllBytes(filePath, encryptedKey);
    }

    public static byte[] ReadFromFile(string filePath)
    {
        return File.ReadAllBytes(filePath);
    }
    
    public static byte[] DecryptKey(byte[] encryptedKeyWithSalt, string passphrase)
    {
        using (var aes = new AesManaged())
        {
            // Extract the salt from the encrypted key
            byte[] salt = new byte[16];
            Array.Copy(encryptedKeyWithSalt, 0, salt, 0, 16);

            var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);

            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                // Write the encrypted key (minus the salt)
                cs.Write(encryptedKeyWithSalt, 16, encryptedKeyWithSalt.Length - 16);
                cs.Close();

                return ms.ToArray();
            }
        }
    }
}