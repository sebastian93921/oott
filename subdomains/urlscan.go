package subdomains

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"strings"
)

type Payload struct {
	Results []Result `json:"results"`
	Total   *int     `json:"total"`
}

type Result struct {
	Task       Task          `json:"task"`
	Stats      Stats         `json:"stats"`
	Page       Page          `json:"page"`
	ID         string        `json:"_id"`
	Score      *int          `json:"_score"`
	Sort       []interface{} `json:"sort"`
	Result     string        `json:"result"`
	Screenshot string        `json:"screenshot"`
}

type Task struct {
	Visibility string `json:"visibility"`
	Method     string `json:"method"`
	Domain     string `json:"domain"`
	ApexDomain string `json:"apexDomain"`
	Time       string `json:"time"`
	UUID       string `json:"uuid"`
	URL        string `json:"url"`
}

type Stats struct {
	UniqIPs           int `json:"uniqIPs"`
	UniqCountries     int `json:"uniqCountries"`
	DataLength        int `json:"dataLength"`
	EncodedDataLength int `json:"encodedDataLength"`
	Requests          int `json:"requests"`
}

type Page struct {
	Country      string `json:"country"`
	Server       string `json:"server"`
	Redirected   string `json:"redirected"`
	IP           string `json:"ip"`
	MimeType     string `json:"mimeType"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	TLSValidDays int    `json:"tlsValidDays"`
	TLSAgeDays   int    `json:"tlsAgeDays"`
	TLSValidFrom string `json:"tlsValidFrom"`
	Domain       string `json:"domain"`
	ApexDomain   string `json:"apexDomain"`
	ASNName      string `json:"asnname"`
	ASN          string `json:"asn"`
	TLSIssuer    string `json:"tlsIssuer"`
	Status       string `json:"status"`
}

type Urlscan struct {
	// any necessary fields specific
}

func (s *Urlscan) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Urlscan:", domain)

	// Make the API request
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s", domain)
	resp, err := http.Get(url)
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
		print(string(body))
		return nil, nil
	}

	var subdomains []SubDomainDetails

	// Unmarshal the payload JSON into a slice of Payload structs
	var payloadData Payload
	json.Unmarshal(body, &payloadData)

	for _, p := range payloadData.Results {
		if strings.Contains(p.Task.Domain, domain) {
			subdomain := SubDomainDetails{
				DomainName: p.Task.Domain,
				Source:     "Urlscan",
			}
			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains, nil
}
