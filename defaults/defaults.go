package defaults

import "embed"

//go:embed wappalyzer/*.json
var EmbeddedWappalyzerFiles embed.FS
