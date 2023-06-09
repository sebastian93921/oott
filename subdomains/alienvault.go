package subdomains

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type PassiveDNS struct {
	Address    string `json:"address"`
	Hostname   string `json:"hostname"`
	RecordType string `json:"record_type"`
}

type Alienvault struct {
	// any necessary fields specific
}

func (s *Alienvault) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	fmt.Println("[+] Scanning subdomains on Alienvault:", domain)

	// Make the API request
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
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

	var data map[string]interface{}
	json.Unmarshal(body, &data)

	passiveDNS, ok := data["passive_dns"].([]interface{})
	if !ok {
		fmt.Println("[!] Invalid JSON format")
		return nil, nil
	}

	var subdomains []SubDomainDetails
	for _, item := range passiveDNS {
		entry := item.(map[string]interface{})

		subdomain := SubDomainDetails{
			DomainName: entry["hostname"].(string),
			Type:       entry["record_type"].(string),
			ModuleName: "Alienvault",
		}
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}
