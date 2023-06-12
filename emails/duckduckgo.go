package emails

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

func (s *DuckDuckGo) ScanEmails(domain string) ([]EmailDetails, error) {
	helper.InfoPrintln("[+] Scanning emails on DuckDuckGo:", domain)

	totalResults, err := common.DuckDuckGoSearch(domain, lib.Config.Useragent)
	if err != nil {
		helper.ErrorPrintln(err)
		return nil, err
	}

	elements := s.extractEmailsFromText(totalResults)
	encountered := map[string]bool{}
	var result []EmailDetails
	for v := range elements {
		if encountered[elements[v]] == true {
			continue
		}

		encountered[elements[v]] = true

		if strings.Contains(elements[v], domain) {
			subdomain := EmailDetails{
				Email:  elements[v],
				Source: "DuckDuckGo",
			}
			result = append(result, subdomain)
		}
	}

	return result, nil
}

func (s *DuckDuckGo) extractEmailsFromText(text string) []string {
	// Remove escape characters
	text = html.UnescapeString(text)

	// Remove HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	text = htmlRegex.ReplaceAllString(text, " ")

	// Remove backslash characters
	text = strings.ReplaceAll(text, "\\", "")

	// Regular expression pattern to match email
	emailPattern := `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`

	// Compile the regular expression pattern
	re := regexp.MustCompile(emailPattern)

	// Find all matches in the input text
	matches := re.FindAllString(text, -1)

	return matches
}
