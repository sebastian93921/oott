package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"oott/helper"
	"os"
	"time"
)

type SimpleScan struct {
	ScannedSubdomains []SubDomainDetails
}

type SubdomainTask struct {
	SubdomainTarget string
	DNSServers      []string
	Timeout         time.Duration
}

func (s *SimpleScan) ScanSubdomains(domain string) ([]SubDomainDetails, error) {
	CreateInterruptHandler()
	defer HousekeepInterruptHandler()

	helper.InfoPrintln("[+] Scanning subdomains on SimpleScan:", domain)

	wordlistFilePath := tmpfolder + "/subdomains-prefix.txt"
	timeout := 200 * time.Millisecond // Adjust timeout duration as needed
	workerCount := 100                // Number of worker goroutines

	if IsFastScan {
		timeout = 100 * time.Millisecond // Adjust timeout duration as needed
	}

	// Make sure the worker count cannot higher than the maximum threads
	if ConcurrentRunningThread > workerCount {
		workerCount = ConcurrentRunningThread
	}

	// Download the file
	err := downloadFile(wordlist, wordlistFilePath)
	if err != nil {
		helper.ErrorPrintln("[!] Error downloading file:", err)
		return nil, nil
	}

	helper.InfoPrintln("[+] Files downloaded successfully.")

	subdomainPrefixes := readFileLinebyLine(wordlistFilePath)
	if subdomainPrefixes == nil {
		return nil, nil
	}
	var subdomainsString []string
	// Iterate over the subdomain prefixes
	for _, prefix := range subdomainPrefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		subdomainsString = append(subdomainsString, subdomain)
	}
	helper.InfoPrintln("[+] Load wordlist successfully.")

	dnsServers := []string{
		"8.8.8.8",        // Google Public DNS
		"1.1.1.1",        // Cloudflare DNS
		"208.67.222.222", // OpenDNS
		"9.9.9.9",        // Quad9 DNS
		"64.6.64.6",      // Verisign Public DNS
		"8.26.56.26",     // Comodo Secure DNS
		"199.85.126.20",  // Norton ConnectSafe
		"208.76.50.50",   // Alternate DNS
		"185.228.168.9",  // CleanBrowsing DNS
		"8.8.4.4",        // Google Public DNS Secondary
	}
	if dnsServers == nil {
		return nil, nil
	}

	// Create workers
	taskCh := make(chan SubdomainTask)
	doneCh := make(chan struct{})
	for i := 0; i < workerCount; i++ {
		go func(s *SimpleScan) {
			for task := range taskCh {
				s.simpleSubdomainCheckByTargetAndDns(task.SubdomainTarget, task.DNSServers, task.Timeout)
			}
			doneCh <- struct{}{}
		}(s)
	}

	// Enqueue tasks
	count := 0
	totalSubdomain := len(subdomainsString)
	for _, subdomainStr := range subdomainsString {
		select {
		case <-cancel:
			// Scanner canceled, exit the loop
			break
		default:
			count++
			if VerboseMode {
				helper.VerbosePrintf("[-] Start scanning domain : %-40s Progress: %d/%d - %d%%\n", subdomainStr, count, totalSubdomain, count*100/totalSubdomain)
			}
			task := SubdomainTask{
				SubdomainTarget: subdomainStr,
				DNSServers:      dnsServers,
				Timeout:         timeout,
			}
			taskCh <- task
		}
	}
	close(taskCh)

	// Wait for all workers to finish
	for i := 0; i < workerCount; i++ {
		<-doneCh
	}

	helper.InfoPrintln("[+] SimpleScan Finished, total subdomains found: ", len(s.ScannedSubdomains))
	return s.ScannedSubdomains, nil
}

func readFileLinebyLine(wordlistFilePath string) []string {
	// Open the file for reading
	file, err := os.Open(wordlistFilePath)
	if err != nil {
		helper.ErrorPrintf("[!] Failed to open file: %v\n", err)
		return nil
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	var lines []string
	// Read and print each line
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	return lines
}

func pickRandomDNSServers(dnsServers []string, count int) []string {
	if len(dnsServers) <= count {
		return dnsServers
	}

	// Set a random seed based on the current time
	rand.Seed(time.Now().UnixNano())

	// Shuffle the dnsServers slice
	rand.Shuffle(len(dnsServers), func(i, j int) {
		dnsServers[i], dnsServers[j] = dnsServers[j], dnsServers[i]
	})

	// Take the first 'count' elements as the random subset
	return dnsServers[:count]
}

func (s *SimpleScan) simpleSubdomainCheckByTargetAndDns(subdomainTarget string, dnsServers []string, timeout time.Duration) {
	if VerboseMode {
		helper.VerbosePrintln("[-] Start on subdomain: ", subdomainTarget)
	}
	randomDnsServers := pickRandomDNSServers(dnsServers, 500)
	count := 0
	// Perform DNS lookup using different DNS servers
	for _, dnsServer := range randomDnsServers {
		select {
		case <-cancel:
			// Scanner canceled, exit the loop
			break
		default:
			count++
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{}
					return d.DialContext(ctx, network, dnsServer+":53") // Add 53 port for DNS service
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			addresses, err := resolver.LookupHost(ctx, subdomainTarget)
			if err != nil {
				/* DEBUG Only - Too many outputs
				if VerboseMode {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						// DNS lookup timed out
						helper.VerbosePrintf("[-] DNS lookup timed out for subdomain '%s' on DNS server %s\n", subdomainTarget, dnsServer)
					} else {
						// Subdomain doesn't exist or encountered another error
						helper.VerbosePrintf("[-] Subdomain '%s' does not exist or encountered an error on DNS server %s: %v\n", subdomainTarget, dnsServer, err)
					}
				}
				*/
				continue
			}

			// Subdomain exists, print the IP addresses
			helper.InfoPrintf("[SimpleScan] Subdomain '%s' exists on DNS server %s. IP Address: %s\n", subdomainTarget, dnsServer, addresses[0])

			//If exists, save it and break the loop
			subdomain := SubDomainDetails{
				DomainName: subdomainTarget,
				Address:    addresses[0],
				Source:     "SimpleScan",
			}
			s.ScannedSubdomains = append(s.ScannedSubdomains, subdomain)
			break
		}
	}
}
