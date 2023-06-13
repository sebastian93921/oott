package lib

type Configuration struct {
	Help                    bool
	IsFastScan              bool
	SubdomainScan           bool
	EmailScan               bool
	VerboseMode             bool
	HttpStatusCodeTest      bool
	ConcurrentRunningThread int
	NoExport                bool
	Useragent               string

	SecretScan     bool
	SearchKeywords string
	GitHubAPIToken string
}

var Config Configuration = Configuration{
	Useragent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
}
