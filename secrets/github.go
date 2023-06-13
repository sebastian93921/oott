package secrets

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"oott/common"
	"oott/helper"
	"oott/lib"
)

type Github struct {
	// any necessary fields specific
}

type GithubRepo struct {
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Path        string `json:"path"`
	URL         string `json:"url"`
	HTMLURL     string `json:"html_url"`
	DownloadURL string `json:"download_url"`
}

type Response struct {
	Items []GithubRepo `json:"items"`
}

//go:embed secretpatterns.json
var secretpatternsEmbed embed.FS

func (s *Github) ScanSecrets(domain string) ([]SecretDetails, error) {
	helper.InfoPrintln("[+] Scanning subdomains on Github:", domain)

	// Read patterns
	fileBytes, err := secretpatternsEmbed.ReadFile("secretpatterns.json")
	if err != nil {
		helper.ErrorPrintf("[!] Error reading the pattern file: %s\n", err.Error())
		return nil, err
	}

	// Declare a map to hold the JSON data
	var keyAndRegex map[string]string

	// Unmarshal the JSON data into the map
	err = json.Unmarshal(fileBytes, &keyAndRegex)
	if err != nil {
		helper.ErrorPrintf("[!] Error reading the pattern file: %s\n", err.Error())
		return nil, err
	}

	// Print the key-value pairs
	if lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Using the following regex for secrets scanning..")
		for key, value := range keyAndRegex {
			helper.VerbosePrintf("  +- %s: %v\n", key, value)
		}
	}

	var keywords = []string{domain}

	if lib.Config.SearchKeywords != "" && len(lib.Config.SearchKeywords) >= 0 {
		tempkeywords := strings.Split(lib.Config.SearchKeywords, ",")
		keywords = append(keywords, tempkeywords...)
		helper.InfoPrintln("[+] Secrets search with keywords: ", keywords)
	}

	secretDetails := s.startSearchByKeywords(keywords, keyAndRegex)

	return secretDetails, nil
}

func (s *Github) startSearchByKeywords(keywords []string, searchPatterns map[string]string) []SecretDetails {
	var secretDetails []SecretDetails
	for _, keyword := range keywords {
		helper.InfoPrintln("[+] Start searching with keyword:", keyword)
		githubRepos := common.SearchGithubRepoByKeyword(keyword)
		if githubRepos == nil {
			return nil
		}

		for _, repo := range githubRepos {
			result := s.searchCodeFromGithubRepo(repo, searchPatterns)
			secretDetails = append(secretDetails, result...)
		}
	}
	return secretDetails
}

func (s *Github) searchCodeFromGithubRepo(item common.GithubRepo, searchPatterns map[string]string) []SecretDetails {
	repository := item.Repository.FullName
	path := item.Path
	htmlURL := item.HTMLURL

	rawContent, err := common.ExtractCodeFromGithubRepo(item)
	if err != nil {
		helper.ErrorPrintf("[!] Error fetching the github repo: %s\n", err.Error())
		return nil
	}

	lines := strings.Split(rawContent, "\n")

	return s.searchSecretsByPattern(lines, repository, path, htmlURL, searchPatterns)
}

func (s *Github) searchSecretsByPattern(lines []string, repository string, path string, htmlURL string, searchPatterns map[string]string) []SecretDetails {
	var secrests []SecretDetails
	for key, value := range searchPatterns {
		regex := regexp.MustCompile(value)
		for lineNum, line := range lines {
			lineNumber := lineNum + 1
			line = strings.TrimSpace(line) // Trim it first
			if regex.MatchString(line) {
				helper.InfoPrintf("[+] Repository: %-20s Path: %s\n", repository, path)
				helper.InfoPrintf("[+] Pattern found: %s\n", key)
				helper.InfoPrintf("[+] Line %d: %s\n", lineNumber, line)
				helper.InfoPrintf("[+] GitHub URL: %s#L%d\n", htmlURL, lineNumber)
				helper.InfoPrintln("[+]", strings.Repeat("-", 50))

				secret := SecretDetails{
					PatternName:   key,
					Content:       line,
					ContentSource: fmt.Sprintf("%s#L%d", htmlURL, lineNumber),
					Source:        "GitHub",
				}
				secrests = append(secrests, secret)
			}
		}
	}
	return secrests
}
