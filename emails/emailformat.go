package emails

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

type EmailFormat struct {
}

func (ef *EmailFormat) ScanEmails(domain string) ([]EmailDetails, error) {
	fmt.Println("[+] Scanning emails on EmailFormat:", domain)

	url := fmt.Sprintf("https://www.email-format.com/d/%s/", domain)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}

	content := string(body)
	emails := ef.ExtractEmails(content)
	var emailDetails []EmailDetails
	for _, email := range emails {
		email = strings.ToLower(email)
		if strings.HasSuffix(email, domain) {
			email := EmailDetails{
				Email:  email,
				Source: "EmailFormat",
			}
			emailDetails = append(emailDetails, email)
		}
	}

	return emailDetails, nil
}

func (ef *EmailFormat) ExtractEmails(content string) []string {
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`)
	return emailRegex.FindAllString(content, -1)
}
