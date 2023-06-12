package subdomains

import (
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"oott/helper"
	"regexp"
	"strings"
)

type DuckDuckGo struct {
	TotalResults string
	API          string
}

func (s *DuckDuckGo) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on DuckDuckGo:", domain)

	if s.TotalResults == "" {
		s.API = "https://api.duckduckgo.com/?q=%s&format=json&pretty=1"

		url := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&pretty=1", domain)

		client := &http.Client{}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}
		headers := http.Header{}
		headers.Set("User-Agent", useragent)
		req.Header = headers

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}

		results := string(body)
		s.TotalResults += results

		urls, err := s.Crawl(results)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}

		helper.InfoPrintln("[+] DuckDuckGo found some of the URLs:", urls)

		urls = s.filterURLs(urls)
		for _, url := range urls {
			s.TotalResults += s.fetchResponse(url)
		}

	}

	elements := s.extractURLsFromText(s.TotalResults)
	encountered := map[string]bool{}
	var result []SubDomainDetails
	for v := range elements {
		if encountered[elements[v]] == true {
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
	text = htmlRegex.ReplaceAllString(text, "")

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

func (s *DuckDuckGo) Crawl(text string) ([]string, error) {
	urls := []string{}
	load := make(map[string]interface{})
	err := json.Unmarshal([]byte(text), &load)
	if err != nil {
		return urls, err
	}

	for _, val := range load {
		switch v := val.(type) {
		case int, map[string]interface{}, nil:
			continue
		case []interface{}:
			if len(v) == 0 {
				continue
			}
			dictVal := v[0]
			if dictVal, ok := dictVal.(map[string]interface{}); ok {
				for _, value := range dictVal {
					if value, ok := value.(string); ok && (strings.Contains(value, "https://") || strings.Contains(value, "http://")) {
						urls = append(urls, value)
					}
				}
			}
		case string:
			if v != "" && (strings.Contains(v, "https://") || strings.Contains(v, "http://")) {
				urls = append(urls, v)
			}
		}
	}

	tmp := []string{}
	for _, url := range urls {
		if strings.Contains(url, "<") && strings.Contains(url, "href=") {
			equalIndex := strings.Index(url, "=")
			trueURL := ""
			for _, ch := range url[equalIndex+1:] {
				if ch == '"' {
					tmp = append(tmp, trueURL)
					break
				}
				trueURL += string(ch)
			}
		} else {
			if url != "" {
				tmp = append(tmp, url)
			}
		}
	}
	return tmp, nil
}

func (s *DuckDuckGo) filterURLs(urls []string) []string {
	filteredURLs := []string{}
	for _, url := range urls {
		if strings.Contains(url, "https://") || strings.Contains(url, "http://") {
			filteredURLs = append(filteredURLs, url)
		}
	}
	return filteredURLs
}

func (s *DuckDuckGo) fetchResponse(url string) string {
	if VerboseMode {
		helper.VerbosePrintln("[-] Fetching seperated website from response:", url)
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		helper.ErrorPrintln(err)
		return ""
	}
	headers := http.Header{}
	headers.Set("User-Agent", url)
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		helper.ErrorPrintln(err)
		return ""
	}

	return string(body)
}
