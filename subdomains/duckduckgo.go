package subdomains

import (
	"html"
	"oott/common"
	"oott/helper"
	"oott/lib"
	"regexp"
	"strings"
)

type DuckDuckGo struct {
}

func (s *DuckDuckGo) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on DuckDuckGo:", domain)

	totalResults, err := common.DuckDuckGoSearch(domain, lib.Config.Useragent)
	if err != nil {
		helper.ErrorPrintln(err)
		return nil, err
	}

	elements := s.extractURLsFromText(totalResults)
	encountered := map[string]bool{}
	var result []SubDomainDetails
	for v := range elements {
		if encountered[elements[v]] {
			continue
		}

		encountered[elements[v]] = true

		if strings.Contains(elements[v], domain) {
			// Remove "https://" or "http://" prefix
			domainname := strings.TrimPrefix(elements[v], "https://")
			domainname = strings.TrimPrefix(domainname, "http://")

			subdomain := SubDomainDetails{
				DomainName: domainname,
				Source:     "DuckDuckGo",
			}
			result = append(result, subdomain)
		}
	}

	return result, nil
}

func (s *DuckDuckGo) extractURLsFromText(text string) []string {
	// Remove escape characters
	text = html.UnescapeString(text)

	// Remove HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	text = htmlRegex.ReplaceAllString(text, " ")

	// Remove backslash characters
	text = strings.ReplaceAll(text, "\\", "")

	// Regular expression pattern to match URLs
	urlPattern := `https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+`

	// Compile the regular expression pattern
	re := regexp.MustCompile(urlPattern)

	// Find all matches in the input text
	matches := re.FindAllString(text, -1)

	return matches
}
