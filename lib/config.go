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
}

var Config Configuration
