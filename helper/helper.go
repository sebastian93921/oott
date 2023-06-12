package helper

import (
	"encoding/csv"
	"net/http"
	"oott/lib"
	"os"
	"strconv"
	"time"
)

func GetHttpStatusCode(url string) (string, error) {
	client := http.Client{
		Timeout: time.Second * 2,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	headers := http.Header{}
	headers.Set("User-Agent", lib.Config.Useragent)
	req.Header = headers

	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}

	return strconv.Itoa(resp.StatusCode), nil
}

func OutputCsv(data [][]string) (string, error) {
	filename := "/tmp/oott_subdomain-scan_" + getUnixTimestamp() + ".csv"

	file, err := os.Create(filename)
	if err != nil {
		ErrorPrintln("[!] Something wrong when creating CSV file in /tmp")
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	for _, row := range data {
		err := writer.Write(row)
		if err != nil {
			return "", err
		}
	}

	writer.Flush()

	return filename, nil
}

func getUnixTimestamp() string {
	now := time.Now().Unix()

	return strconv.FormatInt(now, 10)
}
