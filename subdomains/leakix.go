package subdomains

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"oott/lib"
	"strings"
	"time"
)

type Leakix struct {
	// any necessary fields specific
}

func (s *Leakix) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Leakix:", domain)

	// Make the API request
	url := fmt.Sprintf("https://leakix.net/api/subdomains/%s", domain)
	client := http.Client{
		Timeout: time.Second * 2,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("User-Agent", lib.Config.Useragent)
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(string(body), domain) {
		helper.ErrorPrintln(string(body))
		return nil, nil
	}

	// Define a struct to match the JSON structure
	type Subdomain struct {
		Subdomain string `json:"subdomain"`
	}

	// Unmarshal the JSON response into a slice of Subdomain structs
	var subdomains []Subdomain
	err = json.Unmarshal(body, &subdomains)
	if err != nil {
		return nil, err
	}

	var subdomainDetails []SubDomainDetails
	for _, subdomain := range subdomains {
		subdomain := SubDomainDetails{
			DomainName: subdomain.Subdomain,
			Source:     "Leakix",
		}
		subdomainDetails = append(subdomainDetails, subdomain)
	}

	return subdomainDetails, nil
}
