package cli

import (
	"flag"
	"fmt"
	"log"
	"os"
)

type Configuration struct {
	Help               bool
	IsFastScan         bool
	SubdomainScan      bool
	VerboseMode        bool
	HttpStatusCodeTest bool
}

var config Configuration

func Start() {
	domain := flag.String("domain", "", "Domain to scan for subdomains")
	flag.BoolVar(&config.Help, "help", false, "Show help")
	flag.BoolVar(&config.SubdomainScan, "subdomain-scan", false, "Perform subdomain scanning by target domain")
	flag.BoolVar(&config.IsFastScan, "fast-scan", false, "Perform fast scanning (Have to combine with different scanning type)")
	flag.BoolVar(&config.HttpStatusCodeTest, "http-status-code", false, "Get HTTP status code for each subdomain found")

	flag.BoolVar(&config.VerboseMode, "verbose", false, "Enable verbose mode")
	flag.Parse()

	if config.Help {
		// Print help details
		fmt.Println("Usage:")
		fmt.Println("  oott [arugments]")
		fmt.Println("Flags:")
		flag.PrintDefaults()

		// Exit the program
		os.Exit(0)
	}

	if *domain == "" {
		log.Fatal("[!] Please provide the '-domain' argument")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if config.SubdomainScan {
		StartSubDomainScan(config, *domain)
	}
}
