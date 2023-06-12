package cli

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
)

type Configuration struct {
	Help                    bool
	IsFastScan              bool
	SubdomainScan           bool
	EmailScan               bool
	VerboseMode             bool
	HttpStatusCodeTest      bool
	ConcurrentRunningThread int
}

var config Configuration

var cancel = make(chan struct{})

func Start() {
	domain := flag.String("domain", "", "Domain to scan for subdomains.")
	domain = flag.String("d", "", "Domain to scan for subdomains (shorthand).")

	flag.BoolVar(&config.Help, "help", false, "Show help.")
	flag.BoolVar(&config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain.")
	flag.BoolVar(&config.EmailScan, "email-scan", false, "Perform email scanning by target domain.")
	flag.BoolVar(&config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
	flag.BoolVar(&config.HttpStatusCodeTest, "http-status-scan", false, "Get HTTP status code for each subdomain found.")

	flag.IntVar(&config.ConcurrentRunningThread, "threads", 500, "Maximum number of Concurrent thread uses.")
	flag.IntVar(&config.ConcurrentRunningThread, "t", 500, "Maximum number of Concurrent thread uses (shorthand).")

	flag.BoolVar(&config.VerboseMode, "verbose", false, "Enable verbose mode")
	flag.BoolVar(&config.VerboseMode, "v", false, "Enable verbose mode (shorthand)")
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

	if config.VerboseMode {
		helper.VerbosePrintln("[-] Verbose mode is enabled, resulting in more detailed console output.")
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
		if config.VerboseMode {
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
