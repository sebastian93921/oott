package cli

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"oott/subdomains"
)

type Configuration struct {
	Help               bool
	IsFastScan         bool
	SubdomainScan      bool
	VerboseMode        bool
	HttpStatusCodeTest bool
}

var config Configuration

func Start() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	flag.BoolVar(&config.Help, "help", false, "Show help")
	flag.BoolVar(&config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain")
	flag.BoolVar(&config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
	flag.BoolVar(&config.HttpStatusCodeTest, "http-status-code", false, "Get HTTP status code for each subdomain found")

	flag.BoolVar(&config.VerboseMode, "verbose", false, "Enable verbose mode")
	flag.Parse()

	if config.Help {
		// Print help details
		fmt.Println("Usage:")
		fmt.Println("  oott [arugments]")
		fmt.Println("Flags:")
		flag.PrintDefaults()

		// Exit the program
		os.Exit(0)
	}

	if *domain == "" {
		log.Fatal("[!] Please provide the '-domain' argument")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if config.SubdomainScan {

		fmt.Println("[+] Scanning subdomains...")

		subdomains.IsFastScan = config.IsFastScan
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

		// Group the results by domain
		groupedResults := make(map[string][]subdomains.SubDomainDetails)
		for _, result := range subdomainLists {
			domain := result.DomainName
			groupedResults[domain] = append(groupedResults[domain], result)
		}

		for domain, results := range groupedResults {
			fmt.Println("Domain:", domain)
			for _, subdomain := range results {
				fmt.Printf("  +- Address: %-40s Type: %-10s Source: %s\n", subdomain.Address, subdomain.Type, subdomain.ModuleName)
			}
			if config.HttpStatusCodeTest {
				client := http.Client{
					Timeout: time.Second * 2,
				}

				resp, err := client.Get("https://" + domain)
				if err == nil {
					fmt.Printf("    +- HTTPS status code: %d\n", resp.StatusCode)
				}

				resp, err = client.Get("http://" + domain)
				if err == nil {
					fmt.Printf("    +- HTTP status code: %d\n", resp.StatusCode)
				}
			}
		}
		fmt.Println("[+] End of subdomains scan")
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
