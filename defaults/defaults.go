package defaults

import "embed"

//go:embed wappalyzer/*.json
var EmbeddedWappalyzerFiles embed.FS

//go:embed secretpatterns.json
var SecretpatternsEmbed embed.FS