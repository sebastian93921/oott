package subdomains

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"regexp"
	"strings"
)

type Archiveorg struct {
	// any necessary fields specific
}

func (s *Archiveorg) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Archiveorg:", domain)

	// Make the API request
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&matchType=domain&output=json&fl=original&collapse=original", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var urls [][]string
	err = json.Unmarshal(body, &urls)
	if err != nil {
		return nil, err
	}

	domainSubdomains := make(map[string]bool)

	for _, url := range urls {
		if len(url) > 0 {
			domainSubdomain := extractDomainSubdomain(url[0])
			if domainSubdomain != "" {
				domainSubdomains[domainSubdomain] = true
			}
		}
	}

	var distinctList []string
	for domainSubdomain := range domainSubdomains {
		distinctList = append(distinctList, domainSubdomain)
	}

	helper.VerbosePrintln("[-] Distinct Domain and Subdomain Names..")
	var subdomains []SubDomainDetails
	for _, domainSubdomain := range distinctList {
		subdomain := SubDomainDetails{
			DomainName: domainSubdomain,
			Source:     "Archiveorg",
		}
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func extractDomainSubdomain(url string) string {
	r, _ := regexp.Compile(`^https?:\/\/([^/^@^?]+):?`)
	matches := r.FindStringSubmatch(url)
	if len(matches) > 1 {
		if strings.Contains(matches[1], "crypto.com") {
			return matches[1]
		}
	}
	return ""
}
