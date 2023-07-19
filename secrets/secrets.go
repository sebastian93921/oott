package secrets

import (
	"os"
	"os/signal"
	"syscall"

	"oott/helper"
)

type SecretScanner interface {
	ScanSecrets(domain string) ([]SecretDetails, error)
}

type SecretDetails struct {
	PatternName   string
	Content       string
	ContentSource string
	Source        string
}

// Cancel Sign handling
var cancel = make(chan struct{})

// Use `defer CloseInterruptHandler()` for housekeeping the signal
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
		helper.ErrorPrintln("\n[!] Ctrl+C pressed. Exiting...")

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
}
