package subdomains

type SubDomainScanner interface {
	ScanSubdomains(domain string) ([]SubDomainDetails, error)
}

type SubDomainDetails struct {
	DomainName string
	Address    string
	Type       string
	ModuleName string
}

// List of subdomain prefixes
var wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
var wordlist_long = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
var resolversUrl = "https://public-dns.info/nameservers.txt"

// Cancel Sign handling
var cancel = make(chan struct{})

var IsFastScan = false
