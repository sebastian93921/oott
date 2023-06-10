package helper

import (
	"encoding/csv"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func GetHttpStatusCode(url string) (string, error) {
	client := http.Client{
		Timeout: time.Second * 2,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}

	return strconv.Itoa(resp.StatusCode), nil
}

func OutputCsv(data [][]string) (string, error) {
	filename := "/tmp/oott_subdomain-scan_" + getUnixTimestamp() + ".csv"

	file, err := os.Create(filename)
	if err != nil {
		log.Println("Something wrong when creating CSV file in /tmp")
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
