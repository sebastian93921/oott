package subdomains

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"oott/helper"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type Rapiddns struct {
	// any necessary fields specific
}

func (s *Rapiddns) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Rapiddns:", domain)

	// Make the API request
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1#result", domain)
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

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		helper.ErrorPrintln("[!] Error parsing HTML:", err)
		return nil, nil
	}

	var subdomains []SubDomainDetails

	rows := doc.Find("tr")

	rows.Each(func(i int, row *goquery.Selection) {
		domain := row.Find("td:nth-child(2)").Text()
		address := row.Find("td:nth-child(3) a").Text()
		domaintype := row.Find("td:nth-child(4)").Text()

		subdomain := SubDomainDetails{
			DomainName: domain,
			Address:    address,
			Type:       domaintype,
			Source:     "Rapiddns",
		}

		subdomains = append(subdomains, subdomain)
	})

	return subdomains, nil
}
