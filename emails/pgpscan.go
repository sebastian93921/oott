package emails

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type PGPScan struct {
}

func (p *PGPScan) ScanEmails(domain string) ([]EmailDetails, error) {
	fmt.Println("[+] Scanning emails on PGPScan:", domain)

	searchURLs := []string{
		"https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=vindex&search=" + domain,
		"https://pgp.surfnet.nl/pks/lookup?fingerprint=on&op=vindex&search=" + domain,
		"http://the.earth.li:11371/pks/lookup?fingerprint=on&op=vindex&search=" + domain,
	}

	deduplicated := make(map[string]bool)
	for _, url := range searchURLs {
		client := http.Client{
			Timeout: time.Second * 10,
		}
		response, err := client.Get(url)
		if err != nil {
			fmt.Println("[!] Error on querying server:", err)
			continue
		}

		if response.StatusCode == http.StatusOK {
			fmt.Printf("[+] Got results from %s:\n", url)
			content := response.Body
			defer content.Close()

			data, err := io.ReadAll(content)
			if err != nil {
				fmt.Println("[!] Error on querying server:", err)
				continue
			}

			regex := `(?i)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`
			re := regexp.MustCompile(regex)
			matches := re.FindAllString(string(data), -1)

			// Deduplicate the email addresses using a map
			for _, match := range matches {
				if VerboseMode {
					fmt.Println("[-] Found email from results:", match)
				}
				deduplicated[match] = true
			}

		} else {
			fmt.Printf("Request failed with status code: %d\n", response.StatusCode)
		}
	}

	var emailDetails []EmailDetails
	// Deduplicated email addresses
	for email := range deduplicated {
		if strings.Contains(email, "@"+domain) {
			emailDetail := EmailDetails{
				Email:  email,
				Source: "PGPScan",
			}
			emailDetails = append(emailDetails, emailDetail)
		}
	}

	return emailDetails, nil
}
