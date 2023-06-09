package subdomains

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

type Massdns struct {
	ScannedSubdomains []SubDomainDetails
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

	var subdomainsString []string

	// Iterate over the subdomain prefixes
	for _, prefix := range subdomainPrefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		subdomainsString = append(subdomainsString, subdomain)
	}

	// Call the MassDNS command with the subdomain
	_ = s.runMassDNS(resolversFilePath, subdomainsString)

	return s.ScannedSubdomains, nil
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

func (s *Massdns) runMassDNS(resolversFilePath string, subdomains []string) error {
	// Create a channel to receive the interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal cancellation
	cancel = make(chan struct{})

	// Start a goroutine to listen for the interrupt signal
	go func() {
		// Wait for the interrupt signal
		<-interrupt
		fmt.Println("\n[!] Ctrl+C pressed. Exiting...")
		// Signal cancellation to stop the scanner
		close(cancel)
	}()

	fmt.Println("[+] Size of subdomains generated: ", len(subdomains))
	err := s.runMassDNSByType(resolversFilePath, subdomains, "A")
	if err != nil {
		return err
	}
	err = s.runMassDNSByType(resolversFilePath, subdomains, "AAAA")
	if err != nil {
		return err
	}

	return nil
}

func (s *Massdns) runMassDNSByType(resolversFilePath string, subdomains []string, domaintype string) error {
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
		return err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] Failed to start command: %v\n", err)
		return err
	}

	// Create a scanner to read from the command's output
	scanner := bufio.NewScanner(stdout)

	// Read the output line by line in real time
	total := len(subdomains)
	scanCount := 0
	for scanner.Scan() {
		select {
		case <-cancel:
			// Scanner canceled, exit the loop
			fmt.Println("[+] Cancel sign received, exiting..")
			break
		default:
			line := scanner.Text()
			scanCount++
			// Parse JSON
			var result map[string]interface{}
			err := json.Unmarshal([]byte(line), &result)
			if err != nil {
				fmt.Printf("[!] Failed to parse JSON: %v\n", err)
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
				var address string
				for _, answer := range answers {
					answerMap := answer.(map[string]interface{})
					answerType := answerMap["type"].(string)

					if answerType == domaintype {
						isCorrectType = true
						address = answerMap["data"].(string)
						break
					}
				}

				if isCorrectType {
					// fmt.Println(line)
					fmt.Printf("[MassDNS] Name: %s, Type: %s, Status: %s, Progress: %d/%d(%d%%)\n", name, typeVal, status, scanCount, total, (scanCount * 100 / total))
					subdomain := SubDomainDetails{
						DomainName: strings.TrimSuffix(name, "."),
						Address:    address,
						Type:       typeVal,
						ModuleName: "Massdns",
					}
					s.ScannedSubdomains = append(s.ScannedSubdomains, subdomain)
				}
			}
		}
	}

	// Check if there was any error in scanning
	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Failed to read command output: %v\n", err)
		return err
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		fmt.Printf("[!] Command execution failed: %v\n", err)
		return err
	}

	return nil
}
