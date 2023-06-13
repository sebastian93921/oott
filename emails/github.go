package emails

import (
	"html"
	"oott/common"
	"oott/helper"
	"oott/lib"
	"regexp"
	"strings"
)

type Github struct {
}

func (ef *Github) ScanEmails(domain string) ([]EmailDetails, error) {
	helper.InfoPrintln("[+] Scanning emails on Github:", domain)

	githubRepos := common.SearchGithubRepoByKeyword(domain)
	if githubRepos == nil {
		return nil, nil
	}

	var emails []string
	for _, repo := range githubRepos {
		result := ef.searchEmailFromGithubRepo(repo)
		emails = append(emails, result...)
	}

	var emailDetails []EmailDetails
	encountered := map[string]bool{}
	helper.InfoPrintln("[+] Searching email related to the domain...")
	if lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Emails in the list:", emails)
	}
	for v := range emails {
		if encountered[emails[v]] == true {
			continue
		}

		encountered[emails[v]] = true

		if strings.Contains(emails[v], domain) {
			subdomain := EmailDetails{
				Email:  emails[v],
				Source: "Github",
			}
			emailDetails = append(emailDetails, subdomain)
		}
	}

	return emailDetails, nil
}

func (ef *Github) searchEmailFromGithubRepo(item common.GithubRepo) []string {
	repository := item.Repository.FullName

	if lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Searching email from repos:", repository)
	}

	rawContent, err := common.ExtractCodeFromGithubRepo(item)
	if err != nil {
		helper.ErrorPrintf("[!] Error fetching the github repo: %s\n", err.Error())
		return nil
	}

	lines := strings.Split(rawContent, "\n")

	var emailsList []string
	for _, line := range lines {
		emails := ef.extractEmailsFromText(line)
		emailsList = append(emailsList, emails...)
	}

	if lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Emails found:", emailsList)
	}
	return emailsList
}

func (ef *Github) extractEmailsFromText(text string) []string {
	// Remove escape characters
	text = html.UnescapeString(text)

	// Remove HTML tags
	htmlRegex := regexp.MustCompile(`<[^>]*>`)
	text = htmlRegex.ReplaceAllString(text, " ")

	// Remove backslash characters
	text = strings.ReplaceAll(text, "\\", "")

	// Regular expression pattern to match email
	emailPattern := `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`

	// Compile the regular expression pattern
	re := regexp.MustCompile(emailPattern)

	// Find all matches in the input text
	matches := re.FindAllString(text, -1)

	return matches
}
