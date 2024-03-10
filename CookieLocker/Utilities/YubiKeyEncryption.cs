using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Spectre.Console;
using Yubico.Core.Buffers;
using Yubico.YubiKey;
using Yubico.YubiKey.Piv;
using static Yubico.YubiKey.Cryptography.RsaFormat;

namespace CookieLocker.Utilities;

public class YubiKeyEncryption
{
    private IYubiKeyDevice? YubiKey { get; set; }
    private PivSession? PivSessionConnected { get; set; }
    
    private const byte Slot = PivSlot.KeyManagement;
    

    public YubiKeyEncryption()
    {
        YubiKey = GetDevice();
        
        if (YubiKey == null) return;
        PivSessionConnected = new PivSession(YubiKey);
    }

    private IYubiKeyDevice? GetDevice()
    {
        var list = YubiKeyDevice.FindAll().ToList();
        while (!list.Any())
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[red]YubiKey not found. Insert the YubiKey and try again.[/]");
            AnsiConsole.Prompt(new TextPrompt<string>("Press Enter to continue...").AllowEmpty());
            list = YubiKeyDevice.FindAll().ToList();
        }
        AnsiConsole.Clear();
        return list.First();
    }

    private static bool KeyCollectorPrompt(KeyEntryData keyEntryData)
    {
        switch(keyEntryData.Request)
        {
            case KeyEntryRequest.AuthenticatePivManagementKey:
                keyEntryData.SubmitValue(Hex.HexToBytes("010203040506070801020304050607080102030405060708").ToArray());
                return true;
            case KeyEntryRequest.VerifyPivPin:
                keyEntryData.SubmitValue(Encoding.ASCII.GetBytes("123456"));
                return true;
            case KeyEntryRequest.TouchRequest:
                AnsiConsole.MarkupLine("[yellow]Touch the YubiKey's contact to confirm the operation.[/]");
                return true;
            case KeyEntryRequest.Release:
                return true;
        }
        return false;
    }

    public void GenerateCertificate()
    {
        PivSessionConnected.Connection.Dispose();

        Process.Start("cmd", "/c YubiKeyGen.bat").WaitForExit();
        
        PivSessionConnected = new PivSession(YubiKey);
    }

    private byte[] GetPublicKey()
    {
        X509Certificate2? certificate = null;
        try
        {
            certificate = PivSessionConnected.GetCertificate(Slot);
        }
        catch (InvalidOperationException e)
        {
            AnsiConsole.MarkupLine($"[yellow]No certificate found. Creating a new one.\n[/]");
            GenerateCertificate();
        }
        
        certificate = PivSessionConnected.GetCertificate(Slot);
        
        return certificate.GetPublicKey();
    }
    
    public void EncryptFile(
        string filePath = null!,
        string browserName = null!,
        string profileName = null!)
    {
        byte[] prefix;
        byte[] encryptedKey;
        
        using var aes = Aes.Create();
        
        if (filePath == null!)
        {
            using var fs = new FileStream(Program.EncryptedFile, FileMode.Open, FileAccess.Read);
            using var br = new BinaryReader(fs);
            prefix = br.ReadBytes(12);
            encryptedKey = br.ReadBytes(256);
            aes.IV = br.ReadBytes(16);

            aes.Key = DecryptKey(encryptedKey);
            (filePath, _) = Tools.ParsePrefix(prefix);
        }
        else
        {
            aes.GenerateKey();
            aes.GenerateIV();
            prefix = Tools.PrefixGenerator(browserName, profileName, false);
        }
        
        var fileData = File.ReadAllBytes(filePath);
        var encryptor = aes.CreateEncryptor();
        var encryptedFileData = encryptor.TransformFinalBlock(fileData, 0, fileData.Length);
        
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(GetPublicKey(), out _);
        encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);

        var encryptedFileContent = new byte[prefix.Length + encryptedKey.Length + aes.IV.Length + encryptedFileData.Length];
        
        Buffer.BlockCopy(prefix, 0, encryptedFileContent, 0, prefix.Length);
        Buffer.BlockCopy(encryptedKey, 0, encryptedFileContent, prefix.Length, encryptedKey.Length);
        Buffer.BlockCopy(aes.IV, 0, encryptedFileContent, prefix.Length + encryptedKey.Length, aes.IV.Length);
        Buffer.BlockCopy(encryptedFileData, 0, encryptedFileContent, prefix.Length + encryptedKey.Length + aes.IV.Length, encryptedFileData.Length);
        
        File.WriteAllBytes(Program.EncryptedFile, encryptedFileContent);
        File.Delete(filePath);
    }

    public string DecryptFile()
    {
        using var aes = Aes.Create();
        using var fs = new FileStream(Program.EncryptedFile, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(fs);
        var prefix = br.ReadBytes(12);
        var encryptedKey = br.ReadBytes(256);
        aes.IV = br.ReadBytes(16);
        var encryptedFileData = br.ReadBytes((int)fs.Length - 60);
        
        aes.Key = DecryptKey(encryptedKey);
        var decryptor = aes.CreateDecryptor();
        var fileData = decryptor.TransformFinalBlock(encryptedFileData, 0, encryptedFileData.Length);
        
        
        var (outputFilePath, browserName) = Tools.ParsePrefix(prefix);
        
        if (Tools.IsMoreRecent(outputFilePath))
        {
            if (!AnsiConsole.Confirm("Cookie file is more recent then encrypted one. Do you want to continue?"))
            {
                AnsiConsole.MarkupLine("Exiting...");
                Environment.Exit(0);
            }
        }
        
        File.WriteAllBytes(outputFilePath, fileData);
        
        return browserName;
    }
    
    private byte[] DecryptKey(byte[] encryptedKey)
    {
        PivSessionConnected.KeyCollector = KeyCollectorPrompt;
        var paddedKey = PivSessionConnected.Decrypt(Slot, encryptedKey);
        _ = TryParsePkcs1Decrypt(paddedKey, out var key);
        
        return key;
    }
    
}