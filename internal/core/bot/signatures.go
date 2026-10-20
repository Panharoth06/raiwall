package bot

// BotCategory categorizes the detected client type.
type BotCategory string

const (
	BotCategoryUnknown BotCategory = "unknown"
	BotCategoryBrowser BotCategory = "browser"
	BotCategoryCLI     BotCategory = "cli_tool"
	BotCategoryLibrary BotCategory = "http_library"
	BotCategoryScanner BotCategory = "scanner"
	BotCategoryCrawler BotCategory = "crawler"
)

// KnownSignature associates a JA4 fingerprint with an automated client or tool identity.
type KnownSignature struct {
	ToolName    string
	BotCategory BotCategory
	Description string
}

// DefaultKnownSignatures contains catalogs of known tool fingerprints for CLI tools,
// HTTP libraries, vulnerability scanners, and automated clients.
var DefaultKnownSignatures = map[string]KnownSignature{
	// Python Requests / Urllib
	"t13d1516h2_8daaf6152771_0100742d1fc0": {
		ToolName:    "python-requests",
		BotCategory: BotCategoryLibrary,
		Description: "Python Requests / Urllib TLS 1.3 Client",
	},
	"t13d151600_8daaf6152771_0100742d1fc0": {
		ToolName:    "python-requests-h1",
		BotCategory: BotCategoryLibrary,
		Description: "Python Requests without ALPN",
	},
	"t12d151600_8daaf6152771_0100742d1fc0": {
		ToolName:    "python-urllib-tls12",
		BotCategory: BotCategoryLibrary,
		Description: "Python Urllib TLS 1.2 Client",
	},

	// cURL
	"t13d1516h2_curl_default": {
		ToolName:    "curl",
		BotCategory: BotCategoryCLI,
		Description: "cURL HTTP/2 TLS 1.3 Client",
	},
	"t13d1909h2_8daaf6152771_0100742d1fc0": {
		ToolName:    "curl",
		BotCategory: BotCategoryCLI,
		Description: "cURL OpenSSL default TLS 1.3",
	},
	"t12d1508h1_8daaf6152771_0100742d1fc0": {
		ToolName:    "curl-tls12",
		BotCategory: BotCategoryCLI,
		Description: "cURL TLS 1.2 Client",
	},

	// Go HTTP Client
	"t13d1516h2_go_http_client": {
		ToolName:    "Go-http-client",
		BotCategory: BotCategoryLibrary,
		Description: "Go net/http standard client",
	},
	"t13d0806h2_8daaf6152771_0100742d1fc0": {
		ToolName:    "Go-http-client",
		BotCategory: BotCategoryLibrary,
		Description: "Go net/http TLS 1.3 client",
	},

	// Scanners
	"t13d1516h2_sqlmap_client": {
		ToolName:    "sqlmap",
		BotCategory: BotCategoryScanner,
		Description: "sqlmap automated SQL injection tool",
	},
	"t13d050500_scanner_zgrab": {
		ToolName:    "zgrab",
		BotCategory: BotCategoryScanner,
		Description: "ZGrab network scanner",
	},
	"t13d050500_scanner_nuclei": {
		ToolName:    "nuclei",
		BotCategory: BotCategoryScanner,
		Description: "Nuclei vulnerability scanner",
	},
}

// KnownBrowserJA4Prefixes contains known legitimate browser prefixes.
// Browsers almost always include SNI ('d'), ALPN ('h2' or 'h1'), and high extension counts.
var KnownToolUAPatterns = []struct {
	Substr   string
	Category BotCategory
	ToolName string
}{
	// Scanners (High risk)
	{Substr: "sqlmap", Category: BotCategoryScanner, ToolName: "sqlmap"},
	{Substr: "nikto", Category: BotCategoryScanner, ToolName: "nikto"},
	{Substr: "nuclei", Category: BotCategoryScanner, ToolName: "nuclei"},
	{Substr: "zgrab", Category: BotCategoryScanner, ToolName: "zgrab"},
	{Substr: "nmap", Category: BotCategoryScanner, ToolName: "nmap"},
	{Substr: "masscan", Category: BotCategoryScanner, ToolName: "masscan"},
	{Substr: "gobuster", Category: BotCategoryScanner, ToolName: "gobuster"},
	{Substr: "dirbuster", Category: BotCategoryScanner, ToolName: "dirbuster"},
	{Substr: "ffuf", Category: BotCategoryScanner, ToolName: "ffuf"},
	{Substr: "wpscan", Category: BotCategoryScanner, ToolName: "wpscan"},

	// CLI tools
	{Substr: "curl/", Category: BotCategoryCLI, ToolName: "curl"},
	{Substr: "Wget/", Category: BotCategoryCLI, ToolName: "wget"},
	{Substr: "HTTPie/", Category: BotCategoryCLI, ToolName: "httpie"},
	{Substr: "aria2/", Category: BotCategoryCLI, ToolName: "aria2"},

	// Libraries
	{Substr: "python-requests", Category: BotCategoryLibrary, ToolName: "python-requests"},
	{Substr: "Python-urllib", Category: BotCategoryLibrary, ToolName: "python-urllib"},
	{Substr: "aiohttp", Category: BotCategoryLibrary, ToolName: "aiohttp"},
	{Substr: "Go-http-client", Category: BotCategoryLibrary, ToolName: "go-http-client"},
	{Substr: "Apache-HttpClient", Category: BotCategoryLibrary, ToolName: "apache-httpclient"},
	{Substr: "okhttp", Category: BotCategoryLibrary, ToolName: "okhttp"},
	{Substr: "node-fetch", Category: BotCategoryLibrary, ToolName: "node-fetch"},
	{Substr: "axios/", Category: BotCategoryLibrary, ToolName: "axios"},

	// Headless / Automation Drivers
	{Substr: "HeadlessChrome", Category: BotCategoryCrawler, ToolName: "headless-chrome"},
	{Substr: "PhantomJS", Category: BotCategoryCrawler, ToolName: "phantomjs"},
	{Substr: "Selenium", Category: BotCategoryCrawler, ToolName: "selenium"},
	{Substr: "Puppeteer", Category: BotCategoryCrawler, ToolName: "puppeteer"},
	{Substr: "Playwright", Category: BotCategoryCrawler, ToolName: "playwright"},
}
