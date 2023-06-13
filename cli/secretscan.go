package cli

import (
	"fmt"
	"strings"

	"oott/helper"
	"oott/lib"
	"oott/secrets"
)

func StartSecretScan(domain string) []secrets.SecretDetails {
	helper.InfoPrintln("[+] Scanning subdomains...")

	secretsScanner := []secrets.SecretScanner{
		&secrets.Github{}, // Need API Key
		// Add more SubDomainScanner implementations here
	}

	helper.InfoPrintln("[+] Below is the list of modules that will be used for secrets scanning against target [", domain, "]")
	helper.InfoPrintln("[+] Fast Scan enabled [", lib.Config.IsFastScan, "]")
	helper.InfoPrintln("[+] Maximum number of concurrent thread [", lib.Config.ConcurrentRunningThread, "]")
	helper.InfoPrintln("========================================================================================>")
	for _, sf := range secretsScanner {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		helper.ResultPrintln(parts[len(parts)-1])
	}
	helper.InfoPrintln("<========================================================================================")
	helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
	fmt.Scanln()

	var secretsLists []secrets.SecretDetails
	for _, ss := range secretsScanner {
		secretResults, err := ss.ScanSecrets(domain)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
		}

		for _, result := range secretResults {
			secretsLists = append(secretsLists, result)
		}
	}

	helper.InfoPrintln("========================================================================================>")
	// Grouping by PatternName
	groupedData := make(map[string][]secrets.SecretDetails)
	for _, details := range secretsLists {
		groupedData[details.PatternName] = append(groupedData[details.PatternName], details)
	}

	// Print grouped data
	for patternName, details := range groupedData {
		helper.ResultPrintf("Pattern Name: %s\n", patternName)
		for _, detail := range details {
			helper.ResultPrintf("  +- Content Source: %-40s Source: %s \n", detail.ContentSource, detail.Source)
			helper.ResultPrintf("    +- Content: %s \n", detail.Content[0:80])
		}
	}
	helper.InfoPrintln("<========================================================================================")

	return secretsLists
}
