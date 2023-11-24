package lib

import (
	"crypto/tls"
	"net/http"
)

type Configuration struct {
	Help        bool
	Useragent   string
	NoExport    bool
	VerboseMode bool
	Tmpfolder   string

	IsFastScan              bool
	SubdomainScan           bool
	HttpStatusCodeTest      bool
	ConcurrentRunningThread int
	CustomWordlist          string

	EmailScan bool

	SecretScan     bool
	SearchKeywords string
	GitHubAPIToken string

	WebScan bool

	LocalScanOnly bool
	LocalScanPath string

	Crawling bool
}

var Config Configuration = Configuration{
	Useragent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
	Tmpfolder: "/tmp/oott/",
}

var HttpClientTransportSettings = &http.Transport{
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}
