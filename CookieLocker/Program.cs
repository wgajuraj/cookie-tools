using System.Diagnostics;
// using System.Linq;
using System.Text;
using CookieLocker.Ciphering;

namespace CookieLocker;

internal static class Program
{
    private const string SourceFile = @"test_files\cookies.txt";
    private const string DestFile = @"test_files\cat1\cookies_encrypted";
    private const string DestFile2 = @"test_files\cat1\cookies_decrypted.txt";
            
    public static string ByteArrayToString(byte[] byteArray)
    {
        var hex = new StringBuilder(byteArray.Length * 2);
        foreach (var b in byteArray)
            hex.Append($"{b:x2}");
        return hex.ToString();
    }

    public static void DecryptCookies(string pass)
    {
        var encryptedKey = KeyGenerator.ReadFromFile("keys");
        var decryptedKey = KeyGenerator.DecryptKey(encryptedKey, pass);
        var iv = KeyGenerator.GenerateIv();
        var cipher = new Cipher(decryptedKey, iv);
        cipher.DecryptFile(DestFile, DestFile2);
    }
            
    public static void EncryptCookies()
    {
        var iv = KeyGenerator.GenerateIv();
        var key = KeyGenerator.ReadFromFile("keys");
        var cipher0 = new Cipher(key, iv);
        cipher0.EncryptFile(SourceFile, DestFile);
    }

    private static void Main()
    {
        if (!File.Exists("keys"))
        {
            var validAnswer = false;
            while (!validAnswer)
            {
                Console.WriteLine("Key not found. Do you want to encrypt cookies? [Y/N]");
                var ans1 = Console.ReadKey();

                switch (ans1.KeyChar)
                {
                    case 'y':
                        Console.Clear();

                        var key = KeyGenerator.GenerateKey();
                        var iv = KeyGenerator.GenerateIv();
                        Console.Write("Choose a new password: ");
                        var pass = Console.ReadLine();
                        Console.Clear();
                        if (pass != null)
                        {
                            var encryptedKey = KeyGenerator.EncryptKey(key, pass);
                            KeyGenerator.WriteToFile(encryptedKey, "keys");
                        }
                        else
                        {
                            return;
                        }

                        var cipher0 = new Cipher(key, iv);
                        cipher0.EncryptFile(SourceFile, DestFile);
                        Console.WriteLine("File encrypted successfully");
                        validAnswer = true;
                        break;
                    case 'n':
                        Console.Clear();
                        return;
                    default:
                        Console.Clear();
                        break;
                }
            }
        }

        var validSelection = false;
        while (!validSelection)
        {
            validSelection = true;

            Console.WriteLine("(1) Launch Browser");
            Console.WriteLine("(2) Change Password");
            Console.WriteLine("(3) ");
            Console.WriteLine();
            Console.WriteLine("(9) Decrypt cookies");
            Console.WriteLine("(0) Exit");
            Console.WriteLine();

            Console.Write("Select a task: ");
            var task = Console.ReadLine();

            switch (task)
            {
                case "1":
                    Console.Clear();
                    Console.WriteLine("\nBrowser launched...");
                    var process = new Process();
                    process.StartInfo.UseShellExecute = true;
                    process.StartInfo.FileName = "brave";
                    process.Start();

                    break;
                case "2":
                    Console.Clear();
                    Console.WriteLine("\nYou selected Task 2");

                    break;
                case "3":
                    Console.Clear();
                    Console.WriteLine("\nYou selected Task 3");

                    break;

                case "9":
                    Console.Clear();
                    Console.Write("Password: ");
                    var pass = Console.ReadLine();
                    Console.Clear();
                    var encryptedKey = KeyGenerator.ReadFromFile("keys");
                    if (pass != null)
                    {
                        var decryptedKey = KeyGenerator.DecryptKey(encryptedKey, pass);
                        var iv = KeyGenerator.GenerateIv();
                        var cipher = new Cipher(decryptedKey, iv);
                        cipher.DecryptFile(DestFile, DestFile2);
                    }
                    else
                    {
                        return;
                    }

                    break;
                default:
                    validSelection = false;
                    Console.Clear();
                    break;
            }
        }
    }
            

    // TEST //
                
    // Console.WriteLine(key.SequenceEqual(decryptedKey));
    // Console.WriteLine("Key: \t\t" + ByteArrayToString(key));
    // Console.WriteLine("Decrypted Key: \t" + ByteArrayToString(decryptedKey));
    

}