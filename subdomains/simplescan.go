package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"net"
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
	fmt.Println("[+] Scanning subdomains on SimpleScan:", domain)

	wordlistFilePath := tmpfolder + "/subdomains-prefix.txt"
	resolversFilePath := tmpfolder + "/dns-resolvers.txt"
	timeout := 500 * time.Millisecond // Adjust timeout duration as needed
	workerCount := 10                 // Number of worker goroutines

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
	fmt.Println("[+] Load wordlist successfully.")

	dnsServers := readFileLinebyLine(resolversFilePath)
	if subdomainPrefixes == nil {
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
	for _, subdomainStr := range subdomainsString {
		task := SubdomainTask{
			SubdomainTarget: subdomainStr,
			DNSServers:      dnsServers,
			Timeout:         timeout,
		}
		taskCh <- task
	}
	close(taskCh)

	// Wait for all workers to finish
	for i := 0; i < workerCount; i++ {
		<-doneCh
	}

	return s.ScannedSubdomains, nil
}

func readFileLinebyLine(wordlistFilePath string) []string {
	// Open the file for reading
	file, err := os.Open(wordlistFilePath)
	if err != nil {
		fmt.Printf("[!] Failed to open file: %v\n", err)
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

func (s *SimpleScan) simpleSubdomainCheckByTargetAndDns(subdomainTarget string, dnsServers []string, timeout time.Duration) {
	fmt.Println("[+] Start on subdomain: ", subdomainTarget)
	totalDnsservers := len(dnsServers)
	count := 0
	// Perform DNS lookup using different DNS servers
	for _, dnsServer := range dnsServers {
		count++
		fmt.Println("[-] Domain [", subdomainTarget, "] Progress: ", count, "/", totalDnsservers, "-", count*100/totalDnsservers, "%")
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
			// if err, ok := err.(net.Error); ok && err.Timeout() {
			// 	// DNS lookup timed out
			// 	fmt.Printf("DNS lookup timed out for subdomain '%s' on DNS server %s\n", subdomainTarget, dnsServer)
			// } else {
			// 	// Subdomain doesn't exist or encountered another error
			// 	fmt.Printf("Subdomain '%s' does not exist or encountered an error on DNS server %s: %v\n", subdomainTarget, dnsServer, err)
			// }
			continue
		}

		// Subdomain exists, print the IP addresses
		fmt.Printf("Subdomain '%s' exists on DNS server %s. IP Address: %s\n", subdomainTarget, dnsServer, addresses[0])

		//If exists, save it and break the loop
		subdomain := SubDomainDetails{
			DomainName: subdomainTarget,
			Address:    addresses[0],
		}
		s.ScannedSubdomains = append(s.ScannedSubdomains, subdomain)
		break
	}
}
