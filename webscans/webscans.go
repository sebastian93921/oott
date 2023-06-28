package webscans

type WebScanner interface {
	ScanWebsites(domains []string) ([]WebsiteDetails, error)
}

type WebsiteDetails struct {
	DomainName   string
	Technologies []WebsiteDetailTechnology
	StatusCode   string
	Source       string
}

type WebsiteDetailTechnology struct {
	Name    string
	Version string
}
