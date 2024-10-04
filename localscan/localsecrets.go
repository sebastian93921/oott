package localscan

import (
	"encoding/json"
	"fmt"
	"oott/defaults"
	"oott/helper"
	"oott/lib"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// skipChan Sign handling
var skipChan = make(chan struct{})
var skip = false
var lastInterruptTime time.Time

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
			skip = false

			fileContent, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			// Convert byte slice to string
			content := string(fileContent)

			// Split the content by newline
			lines := strings.Split(content, "\n")

			for lineNum, line := range lines {
				if !skip {
					lineNumber := lineNum + 1
					// Check if the file matches any pattern
					matchedFiles = append(matchedFiles, checkByPattern(line, lineNumber, filePath, compiledPatterns)...)
				} else {
					helper.InfoPrintln("File skipped:", filePath)
					break
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

func checkByPattern(line string, lineNumber int, filePath string, compiledPatterns map[string]*regexp.Regexp) []string {
	matchedFiles := make([]string, 0)
	// Check if the file matches any pattern
	for patternName, compiledPattern := range compiledPatterns {
		if compiledPattern.MatchString(line) {
			matchedFiles = append(matchedFiles, fmt.Sprintf("Matched pattern \"%s\" in file: %s Line: %d", patternName, filePath, lineNumber))
		}
	}
	return matchedFiles
}

func StringArrayScanning(content []string, filePath string) ([]string, error) {
	// Read patterns
	fileBytes, err := defaults.SecretpatternsEmbed.ReadFile("secretpatterns.json")
	if err != nil {
		helper.ErrorPrintf("Error reading the pattern file: %s\n", err.Error())
		return nil, err
	}

	patterns := make(map[string]string)
	err = json.Unmarshal(fileBytes, &patterns)
	if err != nil {
		helper.ErrorPrintf("Failed to decode pattern file. Error: %v\n", err)
		return nil, err
	}

	compiledPatterns := make(map[string]*regexp.Regexp)
	for patternName, pattern := range patterns {
		compiledPattern := regexp.MustCompile(pattern)
		compiledPatterns[patternName] = compiledPattern
	}

	matchedFiles := make([]string, 0)
	for _, content := range content {
		// Check if the file matches any pattern
		matchedFiles = append(matchedFiles, checkByPattern(content, 0, filePath, compiledPatterns)...)
	}

	return matchedFiles, nil
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
	createSkipHandler()
	defer closeSkipHandler()

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

func createSkipHandler() {
	// Create a channel to receive the interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal cancellation
	skipChan = make(chan struct{})

	// Start a goroutine to listen for the interrupt signal
	go func() {
		// Wait for the interrupt signal
		sig := <-interrupt
		switch sig {
		case os.Interrupt:
			if time.Since(lastInterruptTime) <= time.Second/2 {
				helper.ErrorPrintln("\n[!] Receive interrupt signal")
				os.Exit(0)
			} else {
				lastInterruptTime = time.Now()
				helper.ErrorPrintln("\n[!] Receive interrupt signal, file skipped, press again to exit")
				skip = true
				createSkipHandler()
			}
		}
	}()

}

func closeSkipHandler() {
	select {
	case _, ok := <-skipChan:
		if !ok {
			return
		}
	default:
		close(skipChan)
	}
}
