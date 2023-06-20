package cli

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
	"oott/lib"
	"oott/subdomains"
)

var (
	cancel    = make(chan struct{})
	interrupt = make(chan os.Signal, 1)
)

func printBanner() {
	helper.CustomizePrintln("========================================================================================>")
	helper.CustomizePrintln("OOTT - OSINT Offensive Toolkit")
	helper.CustomizePrintln("<========================================================================================")
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
	flag.StringVar(&lib.Config.CustomWordlist, "wordlist", "", "Customize wordlist, please use full path for your customize wordlist. eg. wordlist.txt")

	flag.BoolVar(&lib.Config.SecretScan, "secret-scan", false, "Perform secrets scanning by domain name.")
	flag.StringVar(&lib.Config.SearchKeywords, "key-words", "", "Add more keywords in searching. eg. test,test2,test3 - Only valid on Secret scanning")

	flag.BoolVar(&lib.Config.WebScan, "web-scan", false, "Perform web scanning")

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
	helper.ReadFilteringListFile()

	helper.VerbosePrintln("[-] Verbose mode is enabled, resulting in more detailed console output.")

	// Create folder if not exists
	err := os.MkdirAll(lib.Config.Tmpfolder, os.ModePerm)
	if err != nil {
		helper.ErrorPrintln("[!] Error creating download directory:", err)
		os.Exit(1)
	}

	var subDomainDetails []subdomains.SubDomainDetails
	if lib.Config.SubdomainScan {
		// Return subdomain list
		subDomainDetails = StartSubDomainScan(*domain)
	}

	if lib.Config.EmailScan {
		// Return email list
		_ = StartEmailScan(*domain)
	}

	if lib.Config.SecretScan {
		// Return secrets if possible
		_ = StartSecretScan(*domain)
	}

	if lib.Config.WebScan {
		// Return webscan result if possible
		domains := []string{*domain}
		if len(subDomainDetails) > 0 {
			for _, domain := range subDomainDetails {
				domains = append(domains, domain.DomainName)
			}
		}
		_ = StartWebScan(domains)
	}

	helper.InfoPrintln("[+] Please add generated hashes to the filtering list (filter.txt) to filter out the result for next time.")
	helper.InfoPrintln("[+] For email, just add the email to the filtering list (filter.txt).")
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
		helper.ErrorPrintln("\n[!] Receive interrupt signal")
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
