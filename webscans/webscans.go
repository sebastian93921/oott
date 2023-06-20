package webscans

type WebScanner interface {
	ScanWebsites(domains []string) ([]WebsiteDetails, error)
}

type WebsiteDetails struct {
	DomainName   string
	Technologies []string
	Source       string
}
