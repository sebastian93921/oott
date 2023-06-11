package subdomains

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oott/helper"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Massdns struct {
	ScannedSubdomains []SubDomainDetails
	TargetDomain      string
	FalsePositiveHost map[string]int
}

var massdnsCommand = "massdns"
var tmpfolder = "/tmp"

func (s *Massdns) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	CreateInterruptHandler()
	defer HousekeepInterruptHandler()

	helper.InfoPrintln("[+] Scanning subdomains on Massdns:", domain)
	s.TargetDomain = domain

	wordlistFilePath := tmpfolder + "/subdomains-prefix.txt"
	resolversFilePath := tmpfolder + "/dns-resolvers.txt"

	if !isMassDNSInstalled() {
		helper.ErrorPrintln("[!] MassDNS is not installed or not found. Run 'sudo apt install massdns' to install massdns.")
		helper.ErrorPrintln("Press Enter to continue...")
		fmt.Scanln()
		return nil, nil
	}

	// Download the file
	err := downloadFile(resolversUrl, resolversFilePath)
	if err != nil {
		helper.ErrorPrintln("[!] Error downloading file:", err)
		return nil, nil
	}

	if IsFastScan {
		err = downloadFile(wordlist_long, wordlistFilePath)
	} else {
		err = downloadFile(wordlist, wordlistFilePath)
	}
	if err != nil {
		helper.ErrorPrintln("[!] Error downloading file:", err)
		return nil, nil
	}

	helper.InfoPrintln("[+] Files downloaded successfully.")

	// Open the file for reading
	file, err := os.Open(wordlistFilePath)
	if err != nil {
		helper.ErrorPrintf("[!] Failed to open file: %v\n", err)
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

	if IsFastScan {
		// Iterate over the subdomain prefixes
		for _, prefix := range subdomainPrefixes {
			subdomain := fmt.Sprintf("%s.%s", prefix, domain)
			subdomainsString = append(subdomainsString, subdomain)
		}
	} else {
		// Create combinations for subdomain prefix
		helper.InfoPrintln("[+] Generating combination of prefix...")
		var subdomainPrefixesNew []string
		totalCombinations := len(subdomainPrefixes) * len(subdomainPrefixes) * 2
		combinationsGenerated := 0
		generateProcessFinished := false
		// Start a separate goroutine to print progress every 5 seconds
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			for range ticker.C {
				if VerboseMode {
					helper.VerbosePrintln("[-] Generating combination of prefix, please wait... %d/%d\n", combinationsGenerated, totalCombinations)
				}
				if generateProcessFinished {
					return
				}
			}
		}()
		for _, prefix := range subdomainPrefixes {
			for _, prefix2 := range subdomainPrefixes {
				newprefix1 := fmt.Sprintf("%s-%s", prefix, prefix2)
				subdomainPrefixesNew = append(subdomainPrefixesNew, prefix, newprefix1)
				combinationsGenerated += 2
			}
		}
		generateProcessFinished = true
		// Wait for a short duration to allow the last progress update to be printed
		time.Sleep(1 * time.Second)

		// Iterate over the subdomain prefixes
		for _, prefix := range subdomainPrefixesNew {
			subdomain := fmt.Sprintf("%s.%s", prefix, domain)
			subdomainsString = append(subdomainsString, subdomain)
		}
	}

	// Call the MassDNS command with the subdomain
	_ = s.runMassDNS(resolversFilePath, subdomainsString)

	return s.ScannedSubdomains, nil
}

func downloadFile(url string, filePath string) error {
	helper.InfoPrintln("[+] Downloading files from " + url + " ...")
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
	helper.InfoPrintln("[+] Size of subdomains generated: ", len(subdomains), " . Start running, please wait..")
	helper.InfoPrintln("[+] Press Ctrl+C to cancel this operation if it doesn't produce any results for an extended period of time.")
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

func (s *Massdns) runRootScan(resolversFilePath string, domaintype string) []string {
	s.FalsePositiveHost = make(map[string]int)
	// Run a command
	cmd := exec.Command(massdnsCommand, "-r", resolversFilePath, "-t", domaintype, "-o", "J", "-q")

	// Create an io.Reader from the string
	reader := strings.NewReader(s.TargetDomain)
	cmd.Stdin = reader

	// Create a pipe for reading the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		helper.ErrorPrintf("[!] Failed to create pipe: %v\n", err)
		return nil
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		helper.ErrorPrintf("[!] Failed to start command: %v\n", err)
		return nil
	}

	// Create a scanner to read from the command's output
	scanner := bufio.NewScanner(stdout)

	// Read the output line by line in real time
	for scanner.Scan() {
		select {
		case <-cancel:
			// Scanner canceled, exit the loop
			helper.InfoPrintln("[+] Cancel sign received, exiting..")
			break
		default:
			line := scanner.Text()
			// Parse JSON
			var result map[string]interface{}
			err := json.Unmarshal([]byte(line), &result)
			if err != nil {
				helper.ErrorPrintf("[!] Failed to parse JSON: %v\n", err)
				continue
			}

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
				var addresses []string
				for _, answer := range answers {
					answerMap := answer.(map[string]interface{})
					answerType := answerMap["type"].(string)

					if answerType == domaintype {
						addresses = append(addresses, answerMap["data"].(string))
					}
				}

				return addresses

			}
		}
	}

	// Check if there was any error in scanning
	if err := scanner.Err(); err != nil {
		helper.ErrorPrintf("[!] Failed to read command output: %v\n", err)
		return nil
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		helper.ErrorPrintf("[!] Command execution failed: %v\n", err)
		return nil
	}

	return nil
}

func (s *Massdns) runMassDNSByType(resolversFilePath string, subdomains []string, domaintype string) error {
	var subDomainResult []SubDomainDetails
	helper.InfoPrintln("[+] Starting Root Addresses scan for type", domaintype)
	rootAddresses := s.runRootScan(resolversFilePath, domaintype)
	helper.InfoPrintln("[+] Root addresses found: ", rootAddresses)

	helper.InfoPrintln("[+] Starting Subdomain scan for type", domaintype)

	// Run a command
	cmd := exec.Command(massdnsCommand, "-r", resolversFilePath, "-t", domaintype, "-s", "500", "-o", "J", "-q")
	// Create a concatenated string of the list elements
	stronlyDomains := strings.Join(subdomains, "\n")

	// Create an io.Reader from the string
	reader := strings.NewReader(stronlyDomains)
	cmd.Stdin = reader

	// Create a pipe for reading the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		helper.ErrorPrintf("[!] Failed to create pipe: %v\n", err)
		return err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		helper.ErrorPrintf("[!] Failed to start command: %v\n", err)
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
			helper.InfoPrintln("[+] Cancel sign received, exiting..")
			break
		default:
			line := scanner.Text()
			scanCount++
			// Parse JSON
			var result map[string]interface{}
			err := json.Unmarshal([]byte(line), &result)
			if err != nil {
				helper.ErrorPrintf("[!] Failed to parse JSON: %v\n", err)
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
				resolver := result["resolver"].(string)

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
					if s.isFalsePositive(rootAddresses, address) {
						// Not a valid host
						continue
					}
					// helper.VerbosePrintln(line)
					helper.InfoPrintf("[MassDNS] Name: %s, Type: %s, Status: %s, Progress: %d/%d(%d%%), Resolver: %s\n", name, typeVal, status, scanCount, total, (scanCount * 100 / total), resolver)
					subdomain := SubDomainDetails{
						DomainName: strings.TrimSuffix(name, "."),
						Address:    address,
						Type:       typeVal,
						Source:     "Massdns",
					}
					subDomainResult = append(subDomainResult, subdomain)
				}
			}
		}
	}

	// Remove the false positive again
	for _, subdomain := range subDomainResult {
		if !s.isFalsePositive(rootAddresses, subdomain.Address) {
			s.ScannedSubdomains = append(s.ScannedSubdomains, subdomain)
		}
	}

	// Check if there was any error in scanning
	if err := scanner.Err(); err != nil {
		helper.ErrorPrintf("[!] Failed to read command output: %v\n", err)
		return err
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		helper.ErrorPrintf("[!] Command execution failed: %v\n", err)
		return err
	}

	return nil
}

func (s *Massdns) isFalsePositive(rootAddresses []string, address string) bool {
	for _, root := range rootAddresses {
		if root == address {
			return false
		}
	}
	s.FalsePositiveHost[address] = s.FalsePositiveHost[address] + 1
	if IsFastScan {
		// If the address occurs more then 4 times but it's not from our root addresses, it is possible a false possitve
		if s.FalsePositiveHost[address] > 4 {
			return true
		}
	} else {
		// If the address occurs more then 10 times but it's not from our root addresses, it is possible a false possitve
		if s.FalsePositiveHost[address] > 10 {
			return true
		}
	}
	return false
}
