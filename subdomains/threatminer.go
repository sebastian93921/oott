package subdomains

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

type Threatminer struct {
	// any necessary fields specific
}

func (s *Threatminer) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	fmt.Println("[+] Scanning subdomains on Threatminer:", domain)

	// Make the API request
	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
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

	return nil, nil
}
