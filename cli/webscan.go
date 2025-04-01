package cli

import (
	"fmt"
	"os"
	"strings"

	"oott/helper"
	"oott/lib"
	"oott/webscans"
)

func StartWebScan(domains []string) []webscans.WebsiteDetails {
	helper.InfoPrintln("[+] Scanning websites...")

	// Distinct the domains
	distinctMap := make(map[string]bool)

	// Iterate over the string array and add each string to the map
	for _, str := range domains {
		distinctMap[str] = true
	}

	// Create a new array to store the distinct strings
	distinctArray := make([]string, 0, len(distinctMap))

	// Add the keys (distinct strings) from the map to the new array
	for key := range distinctMap {
		distinctArray = append(distinctArray, key)
	}

	// Replace existing
	domains = distinctArray

	webscanners := []webscans.WebScanner{
		&webscans.Crawler{},
		&webscans.Wappalyzer{},
		// Add more WebScanner implementations here
	}

	helper.InfoPrintln("[+] Below is the list of modules that will be used for web scanning against domain(s) ", domains)
	helper.InfoPrintln("[+] Fast Scan enabled [", lib.Config.IsFastScan, "]")
	helper.InfoPrintln("========================================================================================>")
	for _, sf := range webscanners {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		helper.ResultPrintln(parts[len(parts)-1])
	}
	helper.InfoPrintln("<========================================================================================")
	if !lib.Config.SkipPrompt {
		helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
		_, _ = fmt.Scanln()
	}

	var websiteResults []webscans.WebsiteDetails
	for _, sf := range webscanners {
		results, err := sf.ScanWebsites(domains)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
		}

		websiteResults = append(websiteResults, results...)
	}

	// Merge results by DomainName
	mergedResults := make(map[string]webscans.WebsiteDetails)
	for _, result := range websiteResults {
		merged, ok := mergedResults[result.DomainName]
		if !ok {
			// If this is the first WebsiteDetails for this domain, just use it
			mergedResults[result.DomainName] = result
		} else {
			// Otherwise, merge the details
			merged.Technologies = append(merged.Technologies, result.Technologies...)
			merged.Urls = append(merged.Urls, result.Urls...)

			// Add other fields if they are not null
			if result.StatusCode != "" && merged.StatusCode == "" {
				merged.StatusCode = result.StatusCode
			}
			if result.Source != "" && merged.Source == "" {
				merged.Source = result.Source
			}
			if result.CrawlDirectory != "" && merged.CrawlDirectory == "" {
				merged.CrawlDirectory = result.CrawlDirectory
			}

			mergedResults[result.DomainName] = merged
		}
	}

	helper.InfoPrintln("========================================================================================>")
	csvData := [][]string{
		{"Domain", "Technology", "Status Code", "Source", "Urls"},
	}

	// Results
	for domain, result := range mergedResults {
		helper.ResultPrintf("Domain: %-40s Status Code: %-6s Source: %s\n", domain, result.StatusCode, result.Source)

		for _, technology := range result.Technologies {
			technologyName := technology.Name
			if technology.Version != "" {
				technologyName += fmt.Sprintf(" (%s)", technology.Version)
			}
			helper.ResultPrintf("  +- %s\n", technologyName)

			// Add to csvData
			csvData = append(csvData, []string{domain, technologyName, result.StatusCode, result.Source, strings.Join(result.Urls, ",")})
		}

		if len(result.Urls) > 0 {
			helper.ResultPrintf("  +- Extracted URLs: %d\n", len(result.Urls))
		}

		if result.CrawlDirectory != "" {
			helper.ResultPrintln(">> Total Tech: ", len(result.Technologies), ", Files saved in:", result.CrawlDirectory)
			// Check if the diff file exists
			if _, err := os.Stat(result.CrawlDirectory + ".diff"); err == nil {
				helper.ResultPrintln("+> Diff files saved in:", result.CrawlDirectory+".diff", "\n")
			}
		} else {
			helper.ResultPrintln(">> Total Tech: ", len(result.Technologies))
		}
	}
	helper.InfoPrintln("<========================================================================================")

	if !lib.Config.NoExport {
		filename, err := helper.OutputCsv("webscan", csvData)
		if err == nil {
			helper.ResultPrintln("[+] Please find CSV file in", filename)
		}
	}
	helper.InfoPrintln("[+] End of web scan")

	return websiteResults
}
