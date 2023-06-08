package subdomains

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

type Hackertarget struct {
	// any necessary fields specific to hackertarget
}

func (s *Hackertarget) ScanSubdomains(domain string) ([]string, error) {
	fmt.Println("1. Scanning subdomains on hackertarget:", domain)

	// Make the API request
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
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
