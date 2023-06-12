package subdomains

import (
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
)

type SubDomainScanner interface {
	ScanSubdomains(domain string) ([]SubDomainDetails, error)
}

type SubDomainDetails struct {
	DomainName string
	Address    string
	Type       string
	Source     string
}

// List of subdomain prefixes
var wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
var wordlist_long = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
var resolversUrl = "https://public-dns.info/nameservers.txt"

// Cancel Sign handling
var cancel = make(chan struct{})

var IsFastScan = false
var VerboseMode = false
var ConcurrentRunningThread = 500

// Use `defer HousekeepInterruptHandler()` for housekeeping the signal
func CreateInterruptHandler() {
	// Create a channel to receive the interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal cancellation
	cancel = make(chan struct{})

	// Start a goroutine to listen for the interrupt signal
	go func() {
		// Wait for the interrupt signal
		<-interrupt
		if VerboseMode {
			helper.ErrorPrintln("\n[!] Ctrl+C pressed. Exiting...")
		}
		// Signal cancellation to stop the scanner
		close(cancel)
	}()

}

func HousekeepInterruptHandler() {
	select {
	case _, ok := <-cancel:
		if !ok {
			return
		}
	default:
		close(cancel)
	}
}
