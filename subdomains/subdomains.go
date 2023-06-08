package subdomains

type SubDomainScanner interface {
	ScanSubdomains(domain string) ([]string, error)
}
