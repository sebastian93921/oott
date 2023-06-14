package cli

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
	"oott/lib"
)

var (
	cancel    = make(chan struct{})
	interrupt = make(chan os.Signal, 1)
)

func printBanner() {
	helper.VerbosePrintln("========================================================================================>")
	helper.VerbosePrintln("OOTT - OSINT Offensive Toolkit")
	helper.VerbosePrintln("<========================================================================================")
}

func Start() {
	printBanner()

	domain := flag.String("domain", "", "Domain to scan for subdomains.")
	flag.StringVar(domain, "d", "", "Domain to scan for subdomains (shorthand).")

	flag.BoolVar(&lib.Config.Help, "help h", false, "Show help.")
	flag.BoolVar(&lib.Config.Help, "h", false, "Show help. (shorthand)")
	flag.BoolVar(&lib.Config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain.")
	flag.BoolVar(&lib.Config.EmailScan, "email-scan", false, "Perform email scanning by target domain.")
	flag.BoolVar(&lib.Config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
	flag.BoolVar(&lib.Config.HttpStatusCodeTest, "http-status-scan", false, "Get HTTP status code for each subdomain found.")
	flag.BoolVar(&lib.Config.NoExport, "no-export", false, "Disable export CSV features.")

	flag.BoolVar(&lib.Config.SecretScan, "secret-scan", false, "Perform secrets scanning by domain name.")
	flag.StringVar(&lib.Config.SearchKeywords, "key-words", "", "Add more keywords in searching. eg. test,test2,test3 - Only valid on Secret scanning")

	flag.IntVar(&lib.Config.ConcurrentRunningThread, "threads", 500, "Maximum number of Concurrent thread uses.")
	flag.IntVar(&lib.Config.ConcurrentRunningThread, "t", 500, "Maximum number of Concurrent thread uses (shorthand).")

	flag.BoolVar(&lib.Config.VerboseMode, "verbose", false, "Enable verbose mode")
	flag.BoolVar(&lib.Config.VerboseMode, "v", false, "Enable verbose mode (shorthand)")
	flag.Parse()

	if lib.Config.Help {
		// Print help details
		flag.PrintDefaults()

		// Exit the program
		os.Exit(0)
	}

	if *domain == "" {
		helper.ErrorPrintln("[!] Please provide the '-domain / -d' argument")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Read config file
	helper.ReadConfigFile()

	if lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Verbose mode is enabled, resulting in more detailed console output.")
	}

	if lib.Config.SubdomainScan {
		// Return subdomain list
		_ = StartSubDomainScan(*domain)
	}

	if lib.Config.EmailScan {
		// Return email list
		_ = StartEmailScan(*domain)
	}

	if lib.Config.SecretScan {
		// Return secrets if possible
		_ = StartSecretScan(*domain)
	}
}

// Use `defer CloseInterruptHandler()` for housekeeping the signal
func CreateInterruptHandler() {
	// Create a channel to receive the interrupt signal
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// Create a channel to signal cancellation
	cancel = make(chan struct{})

	// Start a goroutine to listen for the interrupt signal
	go func() {
		// Wait for the interrupt signal
		<-interrupt
		if lib.Config.VerboseMode {
			helper.ErrorPrintln("\n[!] Ctrl+C pressed. Exiting...")
		}
		// Signal cancellation to stop the scanner
		CloseInterruptHandler()
	}()

}

func CloseInterruptHandler() {
	select {
	case _, ok := <-cancel:
		if !ok {
			return
		}
	default:
		close(cancel)
	}

	select {
	case _, ok := <-interrupt:
		if !ok {
			return
		}
	default:
		close(interrupt)
	}
}
