package helper

import (
	"github.com/fatih/color"
)

var InfoPrintf = color.New(color.FgWhite).PrintfFunc()
var InfoPrintln = color.New(color.FgWhite).PrintlnFunc()

var ErrorPrintf = color.New(color.FgRed).PrintfFunc()
var ErrorPrintln = color.New(color.FgRed).PrintlnFunc()

var VerbosePrintf = color.New(color.FgYellow).PrintfFunc()
var VerbosePrintln = color.New(color.FgYellow).PrintlnFunc()

var ResultPrintf = color.New(color.FgGreen).PrintfFunc()
var ResultPrintln = color.New(color.FgGreen).PrintlnFunc()