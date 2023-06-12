package subdomains

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"oott/helper"
	"regexp"
	"strings"
)

type CertSpotter struct {
	// any necessary fields specific
}

func (s *CertSpotter) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on GoogleTransparency:", domain)

	results := []string{}
	baseURL := "https://api.certspotter.com"
	nextLink := fmt.Sprintf("/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)

	client := &http.Client{}
	for nextLink != "" {
		req, err := http.NewRequest("GET", baseURL+nextLink, nil)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			helper.ErrorPrintln(err)
			return nil, err
		}

		hostnames := parseResponse(string(body), domain)
		results = append(results, hostnames...)

		nextLink = resp.Header.Get("Link")
		if nextLink != "" {
			nextLink = strings.Split(nextLink, ";")[0]
			nextLink = nextLink[1 : len(nextLink)-1]
		}
	}

	return removeDuplicates(results), nil
}

func parseResponse(response string, domain string) []string {
	hostnameRegex := fmt.Sprintf(`([\w\d][\w\d\-\.]*\.%s)`, strings.ReplaceAll(domain, ".", "\\."))

	hostnames := []string{}
	hostMatches := regexp.MustCompile(hostnameRegex).FindAllStringSubmatch(response, -1)
	for _, match := range hostMatches {
		hostnames = append(hostnames, strings.TrimLeft(match[1], "."))
	}

	return hostnames
}

func removeDuplicates(elements []string) []SubDomainDetails {
	encountered := map[string]bool{}
	var result []SubDomainDetails

	for v := range elements {
		if encountered[elements[v]] == true {
			continue
		}

		encountered[elements[v]] = true

		subdomain := SubDomainDetails{
			DomainName: elements[v],
			Source:     "CertSpotter",
		}
		result = append(result, subdomain)
	}

	return result
}
