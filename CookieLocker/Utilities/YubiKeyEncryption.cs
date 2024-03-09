using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Spectre.Console;
using Yubico.Core.Buffers;
using Yubico.YubiKey;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Piv;

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
        var list = YubiKeyDevice.FindAll();
        if (list.Count() != 0) return list.First();
        AnsiConsole.MarkupLine("[red]YubiKey not found.[/]");
        return null;
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
    
    public byte[] EncryptFile(string filePath)
    {
        X509Certificate2? certificate = null;
        try
        {
            certificate = PivSessionConnected.GetCertificate(Slot);
        }
        catch (InvalidOperationException e)
        {
            AnsiConsole.MarkupLine($"[yellow]No certificate found. Creating a new one.[/]");
            GenerateCertificate();
        }
        
        certificate = PivSessionConnected.GetCertificate(Slot);
        var publicKey = certificate.GetPublicKey();
        
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out _);
        
        var fileBytes = File.ReadAllBytes(filePath);
        return rsa.Encrypt(fileBytes, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] DecryptFile(string filePath)
    {
        var encryptedData = File.ReadAllBytes(filePath);
        
        PivSessionConnected.KeyCollector = KeyCollectorPrompt;

        var formattedData = PivSessionConnected.Decrypt(Slot, encryptedData);
        byte[] decryptedData;
        RsaFormat.TryParsePkcs1Decrypt(formattedData, out decryptedData);
        
        return decryptedData;
    }
    
}