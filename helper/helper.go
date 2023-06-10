package helper

import (
	"net/http"
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
