package subdomains

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"oott/helper"
	"strings"
)

type Leakix struct {
	// any necessary fields specific
}

func (s *Leakix) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Leakix:", domain)

	// Make the API request
	url := fmt.Sprintf("https://leakix.net/api/subdomains/%s", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
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
	json.Unmarshal(body, &subdomains)

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
