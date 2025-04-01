package cli

import (
	"fmt"
	"strings"

	"oott/helper"
	"oott/lib"
	"oott/subdomains"
)

func StartSubDomainScan(domain string) []subdomains.SubDomainDetails {
	helper.InfoPrintln("[+] Scanning subdomains...")

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
		&subdomains.CertSpotter{},
		&subdomains.DuckDuckGo{},
		// Add more SubDomainScanner implementations here
	}

	helper.InfoPrintln("[+] Below is the list of modules that will be used for subdomain scanning against domain [", domain, "]")
	helper.InfoPrintln("[+] Fast Scan enabled [", lib.Config.IsFastScan, "]")
	helper.InfoPrintln("[+] HTTP Status Scan enabled [", lib.Config.HttpStatusCodeTest, "]")
	helper.InfoPrintln("[+] Maximum number of concurrent thread [", lib.Config.ConcurrentRunningThread, "]")
	if lib.Config.CustomWordlist != "" {
		helper.InfoPrintln("[+] Customized wordlist [", lib.Config.CustomWordlist, "]")
	}
	helper.InfoPrintln("========================================================================================>")
	for _, sf := range subdomainScanResults {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		helper.ResultPrintln(parts[len(parts)-1])
	}
	helper.InfoPrintln("<========================================================================================")
	if !lib.Config.SkipPrompt {
		helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
		_, _ = fmt.Scanln()
	}

	var subdomainLists []subdomains.SubDomainDetails
	for _, sf := range subdomainScanResults {
		subdomains, err := sf.ScanSubdomains(domain)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
		}

		for _, subdomain := range subdomains {
			// Filtering
			hashString := helper.CalculateHash(subdomain.DomainName)
			if !lib.FilteringList[hashString] && subdomain.DomainName != "" {
				subdomainLists = append(subdomainLists, subdomain)
			} else {
				helper.VerbosePrintln("[-] Input matches a hash from the filtering list:", subdomain.DomainName)
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
	CreateInterruptHandler()
	defer CloseInterruptHandler()

	csvData := [][]string{
		{"Domain", "Address", "Type", "Source", "SHA256"},
	}

	for domain, results := range groupedResults {
		helper.InfoPrintln("Domain:", domain)
		hashString := helper.CalculateHash(domain)
		helper.ResultPrintf("  +- SHA256: %s \n", hashString)
		for _, subdomain := range results {
			helper.ResultPrintf("    +- Address: %-40s Type: %-10s Source: %s\n", subdomain.Address, subdomain.Type, subdomain.Source)
			csvData = append(csvData, []string{domain, subdomain.Address, subdomain.Type, subdomain.Source, hashString})
		}

		if lib.Config.HttpStatusCodeTest {
			select {
			case <-cancel:
				// Scanner canceled, exit the loop
				helper.InfoPrintln("[+] Cancel sign received, Stop Status Code Test..")
				break
			default:
				// HTTPS
				httpsStatusCode, err := helper.GetHttpStatusCode("https://" + domain)
				if err == nil {
					helper.ResultPrintf("      +- HTTPS status code: %s\n", httpsStatusCode)
				} else {
					helper.ResultPrintf("      +- HTTPS status code: ERR\n")
				}

				// HTTP
				httpStatusCode, err := helper.GetHttpStatusCode("http://" + domain)
				if err == nil {
					helper.ResultPrintf("      +- HTTP status code: %s\n", httpStatusCode)
				} else {
					helper.ResultPrintf("      +- HTTP status code: ERR\n")
				}
			}
		}
	}
	helper.InfoPrintln("<========================================================================================")
	helper.InfoPrintln("[+] End of subdomains scan")

	if !lib.Config.NoExport {
		filename, err := helper.OutputCsv("subdomain_scan", csvData)
		if err == nil {
			helper.ResultPrintln("[+] Please find CSV file in", filename)
		}
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
