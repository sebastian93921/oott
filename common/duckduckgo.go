package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"strings"
)

type DuckDuckGo struct {
	TotalResults string
	API          string
	Useragent    string
}

var duckduckgoCache DuckDuckGo

func DuckDuckGoSearch(domain string, useragent string) (string, error) {
	if duckduckgoCache == (DuckDuckGo{}) {
		helper.VerbosePrintln("[-] Creating new DuckDuckGo search instance...")
		duckduckgoCache = DuckDuckGo{
			API:       "https://api.duckduckgo.com/?q=%s&format=json&pretty=1",
			Useragent: useragent,
		}
		return duckduckgoCache.DuckDuckGoSearch(domain)
	} else {
		helper.VerbosePrintln("[-] Using existing DuckDuckGo search instance...")
		return duckduckgoCache.DuckDuckGoSearch(domain)
	}
}

func (s *DuckDuckGo) DuckDuckGoSearch(domain string) (string, error) {
	if s.TotalResults == "" {
		url := fmt.Sprintf(s.API, domain)

		client := &http.Client{}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			helper.ErrorPrintln(err)
			return "", err
		}
		headers := http.Header{}
		headers.Set("User-Agent", s.Useragent)
		req.Header = headers

		resp, err := client.Do(req)
		if err != nil {
			helper.ErrorPrintln(err)
			return "", err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			helper.ErrorPrintln(err)
			return "", err
		}

		results := string(body)
		s.TotalResults += results

		urls, err := s.UrlSearch(results)
		if err != nil {
			helper.ErrorPrintln(err)
			return "", err
		}

		helper.InfoPrintln("[+] DuckDuckGo found some of the URLs:", urls)

		urls = s.filterURLs(urls)
		for _, url := range urls {
			s.TotalResults += s.fetchResponse(url)
		}

	}

	return s.TotalResults, nil
}

func (s *DuckDuckGo) UrlSearch(text string) ([]string, error) {
	urls := []string{}
	content := make(map[string]interface{})
	err := json.Unmarshal([]byte(text), &content)
	if err != nil {
		return urls, err
	}

	for _, val := range content {
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

	// Remove Html tags
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
	helper.VerbosePrintln("[-] Fetching seperated website from response:", url)

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		helper.ErrorPrintln(err)
		return ""
	}

	return string(body)
}
