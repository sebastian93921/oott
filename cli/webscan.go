package cli

import (
	"fmt"
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
	helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
	fmt.Scanln()

	var websiteResults []webscans.WebsiteDetails
	for _, sf := range webscanners {
		results, err := sf.ScanWebsites(domains)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
		}

		websiteResults = append(websiteResults, results...)
	}

	helper.InfoPrintln("========================================================================================>")
	csvData := [][]string{
		{"Domain", "Technology", "Status Code", "Source"},
	}

	// Results
	for _, result := range websiteResults {
		helper.ResultPrintf("Domain: %-40s Status Code: %-6s Source: %s\n", result.DomainName, result.StatusCode, result.Source)

		for _, technology := range result.Technologies {
			technologyName := technology.Name
			if technology.Version != "" {
				technologyName += fmt.Sprintf(" (%s)", technology.Version)
			}
			helper.ResultPrintf("  +- %s\n", technologyName)

			// Add to csvData
			csvData = append(csvData, []string{result.DomainName, technologyName, result.StatusCode, result.Source})
		}
		helper.ResultPrintln(">> Total:", len(result.Technologies), "\n")
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
