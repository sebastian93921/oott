package cli

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
)

type Configuration struct {
	Help               bool
	IsFastScan         bool
	SubdomainScan      bool
	EmailScan          bool
	VerboseMode        bool
	HttpStatusCodeTest bool
}

var config Configuration

var cancel = make(chan struct{})

func Start() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	flag.BoolVar(&config.Help, "help", false, "Show help")
	flag.BoolVar(&config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain")
	flag.BoolVar(&config.EmailScan, "email-scan", false, "Perform email scanning by target domain")
	flag.BoolVar(&config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
	flag.BoolVar(&config.HttpStatusCodeTest, "http-status-scan", false, "Get HTTP status code for each subdomain found")

	flag.BoolVar(&config.VerboseMode, "verbose", false, "Enable verbose mode")
	flag.Parse()

	if config.Help {
		// Print help details
		flag.PrintDefaults()

		// Exit the program
		os.Exit(0)
	}

	if *domain == "" {
		helper.ErrorPrintln("[!] Please provide the '-domain' argument")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if config.SubdomainScan {
		// Return subdomain list
		_ = StartSubDomainScan(config, *domain)
	}

	if config.EmailScan {
		// Return email list
		_ = StartEmailScan(config, *domain)
	}
}

func interruptHandler() {
	// Create a channel to receive the interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal cancellation
	cancel = make(chan struct{})

	// Start a goroutine to listen for the interrupt signal
	go func() {
		// Wait for the interrupt signal
		<-interrupt
		helper.ErrorPrintln("\n[!] Ctrl+C pressed. Exiting...")
		// Signal cancellation to stop the scanner
		close(cancel)
	}()
}
