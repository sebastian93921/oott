package main

import (
	"flag"
	"fmt"
	"log"

	"oth/subdomains"
)

func main() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Please provide the '-domain' argument")
	}

	fmt.Println("Scanning subdomains...")

	subdomainScanner := []subdomains.SubDomainScanner{
		// &subdomains.Hackertarget{},
		// &subdomains.Leakix{},
		&subdomains.Alienvault{},
		// &subdomains.Archiveorg{},
		// &subdomains.Rapiddns{},
		// &subdomains.Threatminer{},
		// &subdomains.Urlscan{},
		// Add more SubDomainScanner implementations here
	}

	for _, sf := range subdomainScanner {
		subdomains, err := sf.ScanSubdomains(*domain)
		if err != nil {
			log.Fatal(err)
		}

		// Print the subdomains
		fmt.Printf("\nSubdomains found for %s:\n", *domain)
		for _, subdomain := range subdomains {
			fmt.Printf("Domain: %s, Address: %s, Type: %s\n", subdomain.DomainName, subdomain.Address, subdomain.Type)
		}
	}
}
