package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"oott/subdomains"
)

type Configuration struct {
	Help          bool
	IsFastScan    bool
	SubdomainScan bool
	VerboseMode   bool
}

var config Configuration

func main() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	flag.BoolVar(&config.Help, "help", false, "Show help")
	flag.BoolVar(&config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain")
	flag.BoolVar(&config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
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

		for _, subdomain := range subdomainLists {
			fmt.Printf("Domain: %-40s Address: %-40s Type: %-10s Found Module: %s\n", subdomain.DomainName, subdomain.Address, subdomain.Type, subdomain.ModuleName)
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
