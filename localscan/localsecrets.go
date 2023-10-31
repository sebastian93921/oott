package localscan

import (
	"encoding/json"
	"fmt"
	"oott/defaults"
	"oott/helper"
	"oott/lib"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ignoredFolders = []string{"node_modules/", ".git/", ".svn/", ".hg/", ".bzr/"}
var ignoredExtensions = []string{
	".exe", ".so", ".m4a", ".mp3", ".zip", ".rar", ".tar", ".gz", ".7z", ".bin", ".dat", ".iso", ".dll",
	".apk", ".ipa", ".deb", ".rpm", ".dmg", ".exe", ".pyc", ".app", ".msi", ".msp", ".wasm", ".ico",
	".cur", ".avi", ".mp4", ".mov", ".wmv", ".flv", ".mkv", ".m4v", ".swf", ".ogg", ".wav", ".flac",
	".aac", ".wma", ".m3u", ".war", ".ear", ".obj", ".swc", ".test",
}

func shouldIgnoreFolder(folderPath string) bool {
	for _, ignoredFolder := range ignoredFolders {
		if strings.Contains(folderPath, ignoredFolder) {
			return true
		}
	}
	return false
}

func shouldIgnoreFile(filePath string) bool {
	for _, ignoredExtension := range ignoredExtensions {
		if strings.HasSuffix(filePath, ignoredExtension) {
			return true
		}
	}
	return false
}

func scanDirectory(directoryPath string, patterns map[string]string) []string {
	// Compile regex patterns
	compiledPatterns := make(map[string]*regexp.Regexp)
	for patternName, pattern := range patterns {
		compiledPattern := regexp.MustCompile(pattern)
		compiledPatterns[patternName] = compiledPattern
	}

	// Scan the directory
	matchedFiles := make([]string, 0)
	err := filepath.Walk(directoryPath, func(filePath string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fileInfo.IsDir() && shouldIgnoreFolder(filePath) {
			return filepath.SkipDir
		}

		if !fileInfo.IsDir() && !shouldIgnoreFile(filePath) {
			fmt.Println(filePath)

			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			// Convert byte slice to string
			content := string(fileContent)

			// Split the content by newline
			lines := strings.Split(content, "\n")

			for lineNum, line := range lines {
				lineNumber := lineNum + 1
				// Check if the file matches any pattern
				for patternName, compiledPattern := range compiledPatterns {
					if compiledPattern.MatchString(line) {
						matchedFiles = append(matchedFiles, fmt.Sprintf("Matched pattern \"%s\" in file: %s Line: %d", patternName, filePath, lineNumber))
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		helper.ErrorPrintln("Error:", err)
	}

	return matchedFiles
}

func StartLocalSecretsScanOnly() {
	// Read patterns
	fileBytes, err := defaults.SecretpatternsEmbed.ReadFile("secretpatterns.json")
	if err != nil {
		helper.ErrorPrintf("Error reading the pattern file: %s\n", err.Error())
		os.Exit(1)
	}

	patterns := make(map[string]string)
	err = json.Unmarshal(fileBytes, &patterns)
	if err != nil {
		helper.ErrorPrintf("Failed to decode pattern file. Error: %v\n", err)
		os.Exit(1)
	}

	// Get the directory path from command-line argument
	directoryPath := lib.Config.LocalScanPath

	helper.InfoPrintln("[+] Start local secrets scanning..")

	// Perform directory scan
	matchedFiles := scanDirectory(directoryPath, patterns)

	// Print the matched files
	helper.InfoPrintln("========================================================================================>")
	for _, matchedFile := range matchedFiles {
		helper.InfoPrintln(matchedFile)
	}
	if len(matchedFiles) <= 0 {
		helper.InfoPrintln("No any matches found.")
	}
}
