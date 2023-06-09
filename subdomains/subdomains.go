package subdomains

type SubDomainScanner interface {
	ScanSubdomains(domain string) ([]SubDomainDetails, error)
}

type SubDomainDetails struct {
	DomainName string;
	Address string;
	Type string;
}