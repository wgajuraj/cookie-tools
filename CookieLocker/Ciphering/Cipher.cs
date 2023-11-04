using System.Security.Cryptography;

namespace CookieLocker.Ciphering;

public class Cipher
{
    private readonly string _encryptionKey;
    private readonly string _iv;
    public Cipher(byte[] key, byte[] iv)
    {
        _encryptionKey = Convert.ToBase64String(key);
        _iv = Convert.ToBase64String(iv);
    }
    
    public void EncryptFile(string inputFile, string outputFile)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(_encryptionKey);
            aesAlg.IV = Convert.FromBase64String(_iv);

            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
            using (CryptoStream cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, bytesRead);
                }
            }
        }
    }

    public void DecryptFile(string inputFile, string outputFile)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(_encryptionKey);
            aesAlg.IV = Convert.FromBase64String(_iv);

            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
            using (CryptoStream cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, bytesRead);
                }
            }
        }
    }
}