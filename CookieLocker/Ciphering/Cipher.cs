using System.Security.Cryptography;

namespace CookieLocker.Ciphering;

public class Cipher
{
    private readonly string _encryptionKey;
    private readonly string _iv = "j44yJIvFYcntbmkPwrse0w==";
    public Cipher(byte[] key, byte[] iv)
    {
        _encryptionKey = Convert.ToBase64String(key);
        // _iv = Convert.ToBase64String(iv);
    }
    
    public void EncryptFile(string inputFile, string outputFile)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = Convert.FromBase64String(_encryptionKey);
        aesAlg.IV = Convert.FromBase64String(_iv);

        using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
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
        aesAlg.IV = Convert.FromBase64String(_iv);

        using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);
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