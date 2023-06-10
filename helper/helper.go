package helper

import (
	"net/http"
	"strconv"
	"time"
)

func getHttpStatusCode(url string) (string, error) {
	client := http.Client{
		Timeout: time.Second * 2,
	}

	resp, err := client.Get("https://" + url)
	if err != nil {
		return "ERR", err
	}

	return strconv.Itoa(resp.StatusCode), nil
}
