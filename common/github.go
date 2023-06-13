package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"oott/helper"
	"oott/lib"
	"strings"
)

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

var github_url = "https://api.github.com/search/code"

func SearchGithubRepoByKeyword(keywords string) []GithubRepo {
	if lib.Config.GitHubAPIToken == "" || len(lib.Config.GitHubAPIToken) <= 0 {
		helper.ErrorPrintln("[!] No personal access token provided. Process can not be proceed...")
		helper.ErrorPrintln("[!] Please go to https://github.com/settings/tokens to create one, no any permission needed.")
		helper.ErrorPrintln("Press Enter to continue...")
		fmt.Scanln()
		return nil
	}

	headers := map[string]string{
		"Accept":        "application/vnd.github.v3+json",
		"Authorization": "Bearer " + lib.Config.GitHubAPIToken,
	}
	params := map[string]string{
		"q": keywords,
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", github_url, nil)
	if err != nil {
		helper.ErrorPrintf("[!] Error creating request: %s\n", err.Error())
		return nil
	}

	req.Header.Add("Accept", headers["Accept"])
	req.Header.Add("Authorization", headers["Authorization"])
	q := req.URL.Query()
	for key, value := range params {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	response, err := client.Do(req)
	if err != nil {
		helper.ErrorPrintf("[!] Error sending request: %s\n", err.Error())
		return nil
	}
	defer response.Body.Close()

	if response.StatusCode == 200 {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			helper.ErrorPrintf("[!] Error reading response body: %s\n", err.Error())
			return nil
		}

		var responseObject Response
		err = json.Unmarshal(responseBody, &responseObject)
		if err != nil {
			helper.ErrorPrintf("[!] Error unmarshaling response body: %s\n", err.Error())
			return nil
		}

		return responseObject.Items
	} else {
		helper.ErrorPrintf("[!] Error: %s\n", response.Status)
		return nil
	}
}

func ExtractCodeFromGithubRepo(item GithubRepo) (string, error) {
	if lib.Config.GitHubAPIToken == "" || len(lib.Config.GitHubAPIToken) <= 0 {
		helper.ErrorPrintln("[!] No personal access token provided. Process can not be proceed...")
		helper.ErrorPrintln("[!] Please go to https://github.com/settings/tokens to create one, no any permission needed.")
		return "", fmt.Errorf("No personal access token provided. Process can not be proceed...")
	}

	repository := item.Repository.FullName
	path := item.Path
	contentURL := item.URL
	htmlURL := item.HTMLURL

	headers := map[string]string{
		"Accept":        "application/vnd.github.v3+json",
		"Authorization": "Bearer " + lib.Config.GitHubAPIToken,
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", contentURL, nil)
	if err != nil {
		helper.ErrorPrintf("[!] Error creating request: %s\n", err.Error())
		return "", err
	}

	req.Header.Add("Accept", headers["Accept"])
	req.Header.Add("Authorization", headers["Authorization"])

	rawContentResponse, err := client.Do(req)
	if err != nil {
		helper.ErrorPrintf("[!] Error fetching content of the file: %s\n", err.Error())
		return "", err
	}
	defer rawContentResponse.Body.Close()

	rawContentBody, err := ioutil.ReadAll(rawContentResponse.Body)
	if err != nil {
		helper.ErrorPrintf("[!] Error reading raw content response body: %s\n", err.Error())
		return "", err
	}

	var rawContentJSON map[string]interface{}
	err = json.Unmarshal(rawContentBody, &rawContentJSON)
	if err != nil {
		helper.ErrorPrintf("[!] Error unmarshaling raw content response body: %s\n", err.Error())
		return "", err
	}

	if rawContentJSON["download_url"] == nil {
		helper.ErrorPrintf("[!] Error extracting download content [%s]\n", contentURL)
		helper.ErrorPrintln(string(rawContentBody))
		return "", err
	}
	downloadURL := rawContentJSON["download_url"].(string)

	rawContentResponse, err = http.Get(downloadURL)
	if err != nil {
		helper.ErrorPrintf("[!] Error fetching raw content of the file: %s\n", err.Error())
		return "", err
	}
	defer rawContentResponse.Body.Close()

	rawContentBody, err = ioutil.ReadAll(rawContentResponse.Body)
	if err != nil {
		helper.ErrorPrintf("[!] Error reading raw content response body: %s\n", err.Error())
		return "", err
	}

	if lib.Config.VerboseMode {
		helper.VerbosePrintf("[-] Repository: %-20s Path: %s\n", repository, path)
		helper.VerbosePrintf("[-] GitHub URL: %s\n", htmlURL)
		helper.VerbosePrintln("[-]", strings.Repeat("-", 50))
	}

	return string(rawContentBody), nil
}
