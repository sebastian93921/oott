package helper

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"oott/lib"
	"os"

	"github.com/fatih/color"
)

var InfoPrintf = color.New(color.FgWhite).PrintfFunc()
var InfoPrintln = color.New(color.FgWhite).PrintlnFunc()

var ErrorPrintf = color.New(color.FgRed).PrintfFunc()
var ErrorPrintln = color.New(color.FgRed).PrintlnFunc()

var VerbosePrintf = color.New(color.FgYellow).PrintfFunc()
var VerbosePrintln = color.New(color.FgYellow).PrintlnFunc()

var ResultPrintf = color.New(color.FgGreen).PrintfFunc()
var ResultPrintln = color.New(color.FgGreen).PrintlnFunc()

type ConfigFile struct {
	GitHubAPIToken string `json:"github_api_token"`
}

func ReadConfigFile() {
	filePath := "config.json"

	// Check if the config.json file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		emptyConfig := ConfigFile{}
		fileBytes, err := json.MarshalIndent(emptyConfig, "", "  ")
		if err != nil {
			ErrorPrintln("[!] Error creating config file:", err)
			return
		}

		err = ioutil.WriteFile(filePath, fileBytes, 0644)
		if err != nil {
			ErrorPrintln("[!] Error creating config file:", err)
			return
		}

		InfoPrintln("[+] Created an empty config.json file. Please edit the file and provide your configuration values.")
	}

	// Read the JSON config file
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		ErrorPrintln("[!] Error on reading config file:", err)
		return
	}

	tempConfig := ConfigFile{}
	err = json.Unmarshal(fileBytes, &tempConfig)
	if err != nil {
		ErrorPrintln("[!] Error on reading config file:", err)
		return
	}

	// Map the value
	lib.Config.GitHubAPIToken = tempConfig.GitHubAPIToken
}

func ReadFilteringListFile() {
	filteringListFile := "filtering.txt"

	// Check if the filtering list file exists
	_, err := os.Stat(filteringListFile)
	if os.IsNotExist(err) {
		// Create an empty filtering list file
		_, err := os.Create(filteringListFile)
		if err != nil {
			fmt.Println("[!] Error creating filtering file:", err)
			return
		}
		InfoPrintln("[+] Created an empty filtering file. Please edit add filtering Hashes to the file.")
	}

	file, err := os.OpenFile(filteringListFile, os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		ErrorPrintln("[!] Failed to open the file:", err)
		return
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Add the hash value to the filtering list
		lib.FilteringList[line] = true
	}

	if lib.Config.VerboseMode {
		VerbosePrintln("[-] Filtering list defined:", lib.FilteringList)
	}
}

func CalculateHash(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hash := hex.EncodeToString(hasher.Sum(nil))
	return hash
}
