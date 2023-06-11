package emails

import (
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
)

type EmailScanner interface {
	ScanEmails(domain string) ([]EmailDetails, error)
}

type EmailDetails struct {
	Email  string
	Source string
}

// Cancel Sign handling
var cancel = make(chan struct{})

var IsFastScan = false
var VerboseMode = false

func InterruptHandler() {
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
