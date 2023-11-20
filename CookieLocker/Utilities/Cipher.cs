using System.Security.Cryptography;

namespace CookieLocker.Ciphering;

public class Cipher
{
    private readonly string _encryptionKey;
    public Cipher(byte[] key)
    {
        _encryptionKey = Convert.ToBase64String(key);
    }
    
    public void EncryptFile(string inputFile, string outputFile)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(_encryptionKey);
        aesAlg.GenerateIV();

        using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
        
        fsOutput.Write(aesAlg.IV, 0, aesAlg.IV.Length);
        
        using var encryptor = aesAlg.CreateEncryptor();
        using var cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write);
        
        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
        }
    }

    public void DecryptFile(string inputFile, string outputFile)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(_encryptionKey);

        using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

        var iv = new byte[aesAlg.BlockSize / 8];
        var bytesReadIv = fsInput.Read(iv, 0, iv.Length);
        if (bytesReadIv < iv.Length)
        {
            throw new Exception("Failed to read IV from file.");
        }
        aesAlg.IV = iv;
        
        using var decryptor = aesAlg.CreateDecryptor();
        using var cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write);
        
        var buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
        }
    }
}