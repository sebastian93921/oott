package cli

import (
	"fmt"
	"strings"

	"oott/helper"
	"oott/subdomains"
)

func StartSubDomainScan(configuration Configuration, domain string) []subdomains.SubDomainDetails {
	helper.InfoPrintln("[+] Scanning subdomains...")

	subdomains.IsFastScan = configuration.IsFastScan
	subdomains.VerboseMode = configuration.VerboseMode
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

	helper.InfoPrintln("[+] Below is the list of modules that will be used for subdomain scanning against domain [", domain, "]")
	helper.InfoPrintln("[+] Fast Scan enabled [", configuration.IsFastScan, "]")
	helper.InfoPrintln("========================================================================================>")
	for _, sf := range subdomainScanResults {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		helper.ResultPrintln(parts[len(parts)-1])
	}
	helper.InfoPrintln("<========================================================================================")
	helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
	fmt.Scanln()

	var subdomainLists []subdomains.SubDomainDetails
	for _, sf := range subdomainScanResults {
		subdomains, err := sf.ScanSubdomains(domain)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
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

	helper.InfoPrintln("========================================================================================>")
	interruptHandler()

	csvData := [][]string{
		{"Domain", "Address", "Type", "Source"},
	}

	for domain, results := range groupedResults {
		helper.ResultPrintln("Domain:", domain)
		for _, subdomain := range results {
			helper.ResultPrintf("  +- Address: %-40s Type: %-10s Source: %s\n", subdomain.Address, subdomain.Type, subdomain.Source)
			csvData = append(csvData, []string{domain, subdomain.Address, subdomain.Type, subdomain.Source})
		}

		if configuration.HttpStatusCodeTest {
			select {
			case <-cancel:
				// Scanner canceled, exit the loop
				helper.InfoPrintln("[+] Cancel sign received, Stop Status Code Test..")
				break
			default:
				// HTTPS
				httpsStatusCode, err := helper.GetHttpStatusCode("https://" + domain)
				if err == nil {
					helper.ResultPrintf("    +- HTTPS status code: %s\n", httpsStatusCode)
				} else if configuration.VerboseMode {
					helper.ResultPrintf("    +- HTTPS status code: ERR\n")
				}

				// HTTP
				httpStatusCode, err := helper.GetHttpStatusCode("http://" + domain)
				if err == nil {
					helper.ResultPrintf("    +- HTTP status code: %s\n", httpStatusCode)
				} else if configuration.VerboseMode {
					helper.ResultPrintf("    +- HTTP status code: ERR\n")
				}
			}
		}
	}
	helper.InfoPrintln("<========================================================================================")
	helper.InfoPrintln("[+] End of subdomains scan")

	filename, err := helper.OutputCsv(csvData)
	if err == nil {
		helper.ResultPrintln("[+] Please find CSV file in", filename)
	}

	return subdomainLists
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
