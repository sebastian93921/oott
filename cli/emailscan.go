package cli

import (
	"fmt"
	"log"
	"strings"

	"oott/emails"
)

func StartEmailScan(configuration Configuration, domain string) {
	fmt.Println("[+] Scanning emails...")

	emails.IsFastScan = configuration.IsFastScan
	emailScanResults := []emails.EmailScanner{
		&emails.EmailFormat{},
		&emails.PGPScan{},
		// Add more EmailScanner implementations here
	}

	fmt.Println("[+] Below is the list of modules that will be used for email scanning against domain [", domain, "]")
	fmt.Println("[+] Fast Scan enabled [", configuration.IsFastScan, "]")
	fmt.Println("========================================================================================>")
	for _, sf := range emailScanResults {
		structName := fmt.Sprintf("%T", sf)
		parts := strings.Split(structName, ".")
		fmt.Println(parts[len(parts)-1])
	}
	fmt.Println("<========================================================================================")
	fmt.Println("If you agree the uses of modules, press Enter to continue...")
	fmt.Scanln()

	var emailLists []emails.EmailDetails
	emailMap := make(map[string]string)
	for _, sf := range emailScanResults {
		results, err := sf.ScanEmails(domain)
		if err != nil {
			log.Fatal(err)
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
		emailLists = append(emailLists, emails.EmailDetails{
			Email:  email,
			Source: source,
		})
	}

	fmt.Println("========================================================================================>")
	for _, email := range emailLists {
		fmt.Printf("Email: %-60s Source: %s\n", email.Email, email.Source)
	}
	fmt.Println("<========================================================================================")

	fmt.Println("[+] End of email scan")
}
