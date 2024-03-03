namespace CookieLocker.Utilities;

public class BrowserInfo
{
    public string? PathToLocalState { get; set; }
    public string? PathToCookiesFile { get; set; }
    public List<string>? ProfileList { get; set; }
    public string? ProcessName { get; set; }
    public bool NeedDecryption { get; set; }
    public bool ProfilesPossible { get; set; }
    public bool Exists { get; set; }
    public bool IsPrimary { get; set; }
}

public class BrowserData
{
    public BrowserData()
    {
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        const string chromiumDefaultLocalState = @"User Data\Local State";
        const string chromiumDefaultCookies = @"User Data\Default\Network\Cookies";

        Browsers = new Dictionary<string, BrowserInfo>
        {
            {
                "Chrome", new BrowserInfo
                {
                    PathToLocalState = @$"{localAppDataPath}\Google\Chrome\{chromiumDefaultLocalState}",
                    PathToCookiesFile = @$"{localAppDataPath}\Google\Chrome\{chromiumDefaultCookies}",
                    ProfileList = new List<string>(),
                    ProcessName = "chrome",
                    NeedDecryption = true,
                    ProfilesPossible = true
                }
            },
            {
                "MsEdge", new BrowserInfo
                {
                    PathToLocalState = @$"{localAppDataPath}\Microsoft\Edge\{chromiumDefaultLocalState}",
                    PathToCookiesFile = @$"{localAppDataPath}\Microsoft\Edge\{chromiumDefaultCookies}",
                    ProfileList = new List<string>(),
                    ProcessName = "msedge",
                    NeedDecryption = true,
                    ProfilesPossible = true
                }
            },
            {
                "Firefox", new BrowserInfo
                {
                    PathToLocalState = null,
                    PathToCookiesFile = null,
                    ProcessName = "firefox",
                    NeedDecryption = false,
                    ProfilesPossible = false
                }
            },
            {
                "Opera", new BrowserInfo
                {
                    PathToLocalState = @$"{appDataPath}\Opera Software\Opera Stable\Local State",
                    PathToCookiesFile = @$"{appDataPath}\Opera Software\Opera Stable\Default\Network\Cookies",
                    ProcessName = "opera",
                    NeedDecryption = true,
                    ProfilesPossible = false
                }
            },
            {
                "OperaGX", new BrowserInfo
                {
                    PathToLocalState = @$"{appDataPath}\Opera Software\Opera GX Stable\Local State",
                    PathToCookiesFile = @$"{appDataPath}\Opera Software\Opera GX Stable\Network\Cookies",
                    ProcessName = "opera",
                    NeedDecryption = true,
                    ProfilesPossible = false
                }
            },
            {
                "Brave", new BrowserInfo
                {
                    PathToLocalState = @$"{localAppDataPath}\BraveSoftware\Brave-Browser\{chromiumDefaultLocalState}",
                    PathToCookiesFile = @$"{localAppDataPath}\BraveSoftware\Brave-Browser\{chromiumDefaultCookies}",
                    ProfileList = new List<string>(),
                    ProcessName = "brave",
                    NeedDecryption = true,
                    ProfilesPossible = true
                }
            }
        };

        if (Path.Exists(@$"{appDataPath}\Mozilla\Firefox\Profiles"))
        {
            var firefoxProfilePath = Directory.GetDirectories(@$"{appDataPath}\Mozilla\Firefox\Profiles")
                .FirstOrDefault(dir => dir.EndsWith("-release"));

            Browsers["Firefox"].PathToCookiesFile = Path.Combine(firefoxProfilePath, "cookies.sqlite");
        }
        else
        {
            Browsers["Firefox"].Exists = false;
        }

        foreach (var browser in Browsers
                     .Where(browser => Path.Exists(browser.Value.PathToLocalState)))
            browser.Value.Exists = true;

        foreach (var browser in Browsers)
        {
            if (!browser.Value.ProfilesPossible || !browser.Value.Exists) continue;
            var parentDirectory = Directory.GetParent(browser.Value.PathToLocalState).FullName;
            var profileDirectories = Directory.GetDirectories(parentDirectory, "Profile *");

            foreach (var profileDirectory in profileDirectories)
            {
                var cookiesFilePath = Path.Combine(profileDirectory, "Network", "Cookies");
                browser.Value.ProfileList.Add(cookiesFilePath);
            }
        }

        var validBrowsers = Browsers
            .Where(b => b.Value.Exists)
            .ToDictionary(b => b.Key, b => b.Value);

        if (validBrowsers.Count == 0)
        {
            Console.WriteLine("No valid browsers found.");
            Thread.Sleep(2 * 1000);
            Environment.Exit(0);
        }

        var sortedBrowsers = validBrowsers.OrderByDescending(b =>
        {
            var fileInfo = new FileInfo(b.Value.PathToCookiesFile);
            return fileInfo.Exists ? fileInfo.Length : 0;
        }).ToDictionary(b => b.Key, b => b.Value);

        Browsers = sortedBrowsers;
        Browsers[Browsers.Keys.First()].IsPrimary = true;
    }

    public Dictionary<string, BrowserInfo> Browsers { get; set; }
}