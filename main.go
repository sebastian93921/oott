package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"oott/subdomains"
)

func main() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	subdomainScan := flag.Bool("subdomain-scan", false, "Perform subdomain scanning")
	httpStatusCodeTest := flag.Bool("http-status-code", false, "Get HTTP status code for each subdomain found")
	flag.Parse()

	if *domain == "" {
		log.Fatal("[!] Please provide the '-domain' argument")
	}

	if *subdomainScan {

		fmt.Println("[+] Scanning subdomains...")

		subdomainScanResults := []subdomains.SubDomainScanner{
			&subdomains.Hackertarget{}, // Has max API Limit
			&subdomains.Leakix{},
			&subdomains.Alienvault{},
			&subdomains.Archiveorg{},
			&subdomains.Rapiddns{},
			// &subdomains.Threatminer{},
			&subdomains.Urlscan{},
			&subdomains.Massdns{}, // Wildcard subdomain issue
			&subdomains.SimpleScan{},
			// Add more SubDomainScanner implementations here
		}

		var subdomainLists []subdomains.SubDomainDetails
		for _, sf := range subdomainScanResults {
			subdomains, err := sf.ScanSubdomains(*domain)
			if err != nil {
				log.Fatal(err)
			}

			for _, subdomain := range subdomains {
				if subdomain.DomainName != "" {
					subdomainLists = append(subdomainLists, subdomain)
				}
			}

			subdomainLists = aggregateSubDomainDetails(subdomainLists)

		}

		for _, subdomain := range subdomainLists {
			if *httpStatusCodeTest {
				client := http.Client {
					Timeout: time.Second * 2,
				}

				resp, err := client.Get("https://" + subdomain.DomainName)
				if err != nil {
					fmt.Printf("Domain: %-40s HTTP status code: ERR        Address: %-40s Type: %-10s Found Module: %s\n", subdomain.DomainName, subdomain.Address, subdomain.Type, subdomain.ModuleName)
				} else {
					fmt.Printf("Domain: %-40s HTTP status code: %-10d Address: %-40s Type: %-10s Found Module: %s\n", subdomain.DomainName, resp.StatusCode, subdomain.Address, subdomain.Type, subdomain.ModuleName)
				}
			} else {
				fmt.Printf("Domain: %-40s Address: %-40s Type: %-10s Found Module: %s\n", subdomain.DomainName, subdomain.Address, subdomain.Type, subdomain.ModuleName)
			}
		}
	}
}

func aggregateSubDomainDetails(subDomains []subdomains.SubDomainDetails) []subdomains.SubDomainDetails {
	aggregatedSubDomains := make(map[string]subdomains.SubDomainDetails)

	for _, subDomain := range subDomains {
		existingSubDomain, found := aggregatedSubDomains[subDomain.DomainName]

		if found {
			if existingSubDomain.Address != "" && subDomain.Address != "" && existingSubDomain.Address != subDomain.Address {
				// Different addresses, both are needed
				aggregatedSubDomains[subDomain.DomainName+subDomain.Address] = subDomain
			} else if existingSubDomain.Type != "" && subDomain.Type != "" && existingSubDomain.Type != subDomain.Type {
				// Different types, both are needed
				aggregatedSubDomains[subDomain.DomainName+subDomain.Type] = subDomain
			}
			// Duplicate, same address or type, ignore the new one
		} else {
			aggregatedSubDomains[subDomain.DomainName] = subDomain
		}
	}

	result := make([]subdomains.SubDomainDetails, 0, len(aggregatedSubDomains))
	for _, subDomain := range aggregatedSubDomains {
		result = append(result, subDomain)
	}

	return result
}
