package cli

import (
	"fmt"
	"strings"

	"oott/emails"
	"oott/helper"
	"oott/lib"
)

func StartEmailScan(domain string) []emails.EmailDetails {
	helper.InfoPrintln("[+] Scanning emails...")

	emailScanResults := []emails.EmailScanner{
		&emails.EmailFormat{},
		&emails.PGPScan{},
		&emails.DuckDuckGo{},
		&emails.Github{},
		// Add more EmailScanner implementations here
	}

	helper.InfoPrintln("[+] Below is the list of modules that will be used for email scanning against domain [", domain, "]")
	helper.InfoPrintln("[+] Fast Scan enabled [", lib.Config.IsFastScan, "]")
	helper.InfoPrintln("========================================================================================>")
	for _, sf := range emailScanResults {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		helper.ResultPrintln(parts[len(parts)-1])
	}
	helper.InfoPrintln("<========================================================================================")
	if !lib.Config.SkipPrompt {
		helper.InfoPrintln("If you agree the uses of modules, press Enter to continue...")
		_, _ = fmt.Scanln()
	}

	var emailLists []emails.EmailDetails
	emailMap := make(map[string]string)
	for _, sf := range emailScanResults {
		results, err := sf.ScanEmails(domain)
		if err != nil {
			helper.ErrorPrintln("Unexpected Error Occur:", err)
			continue
		}

		for _, result := range results {
			source := result.Source

			// Combine Source for existing email, if already present
			if existingSource, ok := emailMap[result.Email]; ok {
				if !strings.Contains(existingSource, source) {
					source = fmt.Sprintf("%s, %s", existingSource, source)
				}
			}

			emailMap[result.Email] = source
		}
	}

	// Convert map to slice
	for email, source := range emailMap {
		// Filtering
		if !lib.FilteringList[email] {
			emailLists = append(emailLists, emails.EmailDetails{
				Email:  email,
				Source: source,
			})
		} else {
			helper.VerbosePrintln("[-] Input matches from the filtering list:", email)
		}
	}

	helper.InfoPrintln("========================================================================================>")
	for _, email := range emailLists {
		helper.ResultPrintf("Email: %-60s Source: %s\n", email.Email, email.Source)
	}
	helper.InfoPrintln("<========================================================================================")

	helper.InfoPrintln("[+] End of email scan")

	return emailLists
}
