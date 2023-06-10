package emails

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
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
			log.Fatal(err)
		}

		if response.StatusCode == http.StatusOK {
			fmt.Printf("[+] Got results from %s:\n", url)
			content := response.Body
			defer content.Close()

			data, err := io.ReadAll(content)
			if err != nil {
				log.Fatal(err)
			}

			regex := `(?i)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`
			re := regexp.MustCompile(regex)
			matches := re.FindAllString(string(data), -1)

			// Deduplicate the email addresses using a map
			for _, match := range matches {
				fmt.Println("[-] Found email from results:", match)
				deduplicated[match] = true
			}

		} else {
			log.Printf("Request failed with status code: %d\n", response.StatusCode)
		}
	}

	var emailDetails []EmailDetails
	// Deduplicated email addresses
	for email := range deduplicated {
		emailDetail := EmailDetails{
			Email:  email,
			Source: "PGPScan",
		}
		emailDetails = append(emailDetails, emailDetail)
	}

	return emailDetails, nil
}
