package helper

import (
	"bytes"
	"encoding/json"

	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"github.com/yosssi/gohtml"
)

func PrettyHTML(input []byte) (string, error) {
	result := gohtml.Format(string(input))
	return result, nil
}

func PrettyJS(input []byte) (string, error) {
	opts := jsbeautifier.DefaultOptions()
	inputStr := string(input)
	return jsbeautifier.Beautify(&inputStr, opts)
}

func PrettyJson(input []byte) (string, error) {
	// Check if the request body is valid UTF-8
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, input, "", "  ")
	if err != nil {
		return "", err
	}

	return string(prettyJSON.Bytes()), nil
}
