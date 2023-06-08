package subdomains

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Leakix struct {
	// any necessary fields specific to hackertarget
}

func (s *Leakix) ScanSubdomains(domain string) ([]string, error) {
	fmt.Println("2. Scanning subdomains on leakix:", domain)

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

	fmt.Println(string(body))

	// Define a struct to match the JSON structure
	type Subdomain struct {
		Subdomain string `json:"subdomain"`
	}

	// Unmarshal the JSON response into a slice of Subdomain structs
	var subdomains []Subdomain
	json.Unmarshal(body, &subdomains)

	// Extract the subdomain names
	var subdomainNames []string
	for _, subdomain := range subdomains {
		subdomainNames = append(subdomainNames, subdomain.Subdomain)
	}

	return subdomainNames, nil
}
