package emails

import (
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"regexp"
	"strings"
)

type EmailFormat struct {
}

func (ef *EmailFormat) ScanEmails(domain string) ([]EmailDetails, error) {
	helper.InfoPrintln("[+] Scanning emails on EmailFormat:", domain)

	url := fmt.Sprintf("https://www.email-format.com/d/%s/", domain)
	resp, err := http.Get(url)
	if err != nil {
		helper.ErrorPrintln(err)
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		helper.ErrorPrintln(err)
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
