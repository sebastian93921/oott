package subdomains

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type Massdns struct {
	// any necessary fields specific
}

var massdnsCommand = "massdns"
var tmpfolder = "/tmp"

func (s *Massdns) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	fmt.Println("[+] Scanning subdomains on Massdns:", domain)

	wordlistFilePath := tmpfolder + "/subdomains-prefix.txt"
	resolversFilePath := tmpfolder + "/dns-resolvers.txt"

	if !isMassDNSInstalled() {
		fmt.Println("[!] MassDNS is not installed or not found. Run 'sudo apt install massdns' to install massdns.")
		return nil, nil
	}

	// Download the file
	err := downloadFile(resolversUrl, resolversFilePath)
	if err != nil {
		fmt.Println("[!] Error downloading file:", err)
		return nil, nil
	}

	// Download the file
	err = downloadFile(wordlist, wordlistFilePath)
	if err != nil {
		fmt.Println("[!] Error downloading file:", err)
		return nil, nil
	}

	fmt.Println("[+] Files downloaded successfully.")

	// Open the file for reading
	file, err := os.Open(wordlistFilePath)
	if err != nil {
		fmt.Printf("[!] Failed to open file: %v\n", err)
		return nil, nil
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	var subdomainPrefixes []string
	// Read and print each line
	for scanner.Scan() {
		line := scanner.Text()
		subdomainPrefixes = append(subdomainPrefixes, line)
	}

	subdomainEnumerateOutput := tmpfolder + "/temp-domain.txt"

	// Open the file for writing (create new or truncate existing)
	file, err = os.OpenFile(subdomainEnumerateOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("[!] Failed to open file: %v\n", err)
		return nil, nil
	}
	defer file.Close()

	var subdomainsString []string

	// Iterate over the subdomain prefixes
	for _, prefix := range subdomainPrefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		_, err := fmt.Fprintf(file, "%s\n", subdomain)
		if err != nil {
			fmt.Printf("[!] Failed to write domain to file: %v\n", err)
			return nil, nil
		}

		subdomainsString = append(subdomainsString, subdomain)
	}

	fmt.Printf("[+] Domains saved to %s\n", subdomainEnumerateOutput)

	// Call the MassDNS command with the subdomain
	err = runMassDNS(resolversFilePath, subdomainsString)
	if err != nil {
		fmt.Println("Error running MassDNS:", err)
	}

	return nil, nil
}

func downloadFile(url string, filePath string) error {
	fmt.Println("[+] Downloading files from " + url + " ...")
	// Create the output file
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Send an HTTP GET request to the URL
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Check if the response was successful
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("[!] Failed to download file (HTTP status code: %d)", response.StatusCode)
	}

	// Copy the response body to the output file
	_, err = io.Copy(out, response.Body)
	if err != nil {
		return err
	}

	return nil
}

// Check if MassDNS is installed
func isMassDNSInstalled() bool {
	// Define the MassDNS command and arguments
	arguments := []string{"-h"}

	// Execute the MassDNS command with the --version flag
	cmd := exec.Command(massdnsCommand, arguments...)
	_, err := cmd.Output()

	// Check for errors
	if err != nil {
		return false
	}

	return true
}

func runMassDNS(resolversFilePath string, subdomains []string) error {
	// Check for wildcard domain

	fmt.Println("[+] Size of subdomains generated: ", len(subdomains))
	err := runMassDNSByType(resolversFilePath, subdomains, "A")
	if err != nil {
		return err
	}
	err = runMassDNSByType(resolversFilePath, subdomains, "AAAA")
	if err != nil {
		return err
	}
	return nil
}

func runMassDNSByType(resolversFilePath string, subdomains []string, domaintype string) error {
	// Type A first
	cmd := exec.Command(massdnsCommand, "-r", resolversFilePath, "-t", domaintype, "-s", "500", "-o", "J", "-q")
	// Create a concatenated string of the list elements
	stronlyDomains := strings.Join(subdomains, "\n")

	// Create an io.Reader from the string
	reader := strings.NewReader(stronlyDomains)
	cmd.Stdin = reader

	// Create a pipe for reading the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("[!] Failed to create pipe: %v\n", err)
		return nil
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Failed to start command: %v\n", err)
		return nil
	}

	// Create a scanner to read from the command's output
	scanner := bufio.NewScanner(stdout)

	// Read the output line by line in real time
	total := len(subdomains)
	scanCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		scanCount++
		// Parse JSON
		var result map[string]interface{}
		err := json.Unmarshal([]byte(line), &result)
		if err != nil {
			fmt.Printf("Failed to parse JSON: %v\n", err)
			continue
		}

		// Extract name, type, and status
		name := result["name"].(string)
		typeVal := result["type"].(string)
		status := result["status"].(string)

		// Print the extracted values
		if status == "NOERROR" {
			// Access the "data" field
			data := result["data"].(map[string]interface{})

			// Access the "answers" field within "data"
			answers, ok := data["answers"].([]interface{})
			if !ok {
				continue
			}
			// Iterate over the answers
			isCorrectType := false
			for _, answer := range answers {
				answerMap := answer.(map[string]interface{})
				name := answerMap["name"].(string)
				answerType := answerMap["type"].(string)
				fmt.Println("Name:", name)
				fmt.Println("Type:", answerType)

				if answerType == domaintype {
					isCorrectType = true
					break
				}
			}

			if isCorrectType {
				fmt.Println(line)
				fmt.Printf("[MassDNS] Name: %s, Type: %s, Status: %s, Count: %d/%d(%d%%)\n", name, typeVal, status, scanCount, total, (scanCount * 100 / total))
			}
		}
	}

	// Check if there was any error in scanning
	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Failed to read command output: %v\n", err)
		return nil
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		fmt.Printf("[!] Command execution failed: %v\n", err)
		return nil
	}

	return nil
}
