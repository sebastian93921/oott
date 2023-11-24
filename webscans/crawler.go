package webscans

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"oott/helper"
	"oott/lib"
	"oott/localscan"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type Crawler struct {
	// any necessary fields specific
	outputDir string
	done      chan bool
}

func (c *Crawler) ScanWebsites(domains []string) ([]WebsiteDetails, error) {
	helper.InfoPrintln("[+] Scanning URLs in domain:", domains)
	c.outputDir = lib.Config.Tmpfolder + "result/crawler/websites"

	var websiteDetails []WebsiteDetails

	// If the folder not exists, create it
	dirPath := filepath.Dir(c.outputDir)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, err
	}

	for _, domain := range domains {
		c.startLoadingAnimation()
		websiteDetail := &WebsiteDetails{
			DomainName:     domain,
			CrawlDirectory: filepath.Join(c.outputDir, domain),
		}

		if _, err := os.Stat(websiteDetail.CrawlDirectory); err == nil {
			// Check if the target directory exists and remove it if it does
			if _, err := os.Stat(websiteDetail.CrawlDirectory + ".old"); err == nil {
				if err := os.RemoveAll(websiteDetail.CrawlDirectory + ".old"); err != nil {
					return nil, err
				}
			}
			// Rename the output directory
			if err := os.Rename(websiteDetail.CrawlDirectory, websiteDetail.CrawlDirectory+".old"); err != nil {
				return nil, err
			}
		}
		if err := os.MkdirAll(websiteDetail.CrawlDirectory, 0755); err != nil {
			return nil, err
		}

		// Try HTTPS first
		helper.InfoPrintln("[+] Start HTTPS scan..")
		urls, err := c.fetchAndParseURLs(true, domain, "/", make(map[string]bool))
		if err != nil {
			return nil, err
		}

		websiteDetail.Urls = append(websiteDetail.Urls, urls...)

		// Try HTTP
		helper.InfoPrintln("[+] Start HTTP scan..")
		urls, err = c.fetchAndParseURLs(false, domain, "/", make(map[string]bool))
		if err != nil {
			return nil, err
		}

		websiteDetail.Urls = append(websiteDetail.Urls, urls...)

		// Check differences between the old and the new versions
		helper.InfoPrintln("[+] Compare old and new versions..")
		if _, err := os.Stat(websiteDetail.CrawlDirectory + ".diff"); err == nil {
			// Check if the target directory exists and remove it if it does
			if _, err := os.Stat(websiteDetail.CrawlDirectory + ".diff"); err == nil {
				if err := os.RemoveAll(websiteDetail.CrawlDirectory + ".diff"); err != nil {
					return nil, err
				}
			}
		}
		if err := os.MkdirAll(websiteDetail.CrawlDirectory+".diff", 0755); err != nil {
			return nil, err
		}
		c.diffDirectories(domain, websiteDetail.CrawlDirectory, websiteDetail.CrawlDirectory+".old")

		websiteDetails = append(websiteDetails, *websiteDetail)

		// Stop loading animation
		c.done <- true
	}

	return websiteDetails, nil
}

func (c *Crawler) startLoadingAnimation() {
	// Start loading animation
	c.done = make(chan bool)
	go func() {
		loading := "|/-\\"
		i := 0
		for {
			select {
			case <-c.done:
				helper.InfoPrintf("\r \r")
				return
			default:
				helper.InfoPrintf("\r%c\r", loading[i])
				i = (i + 1) % len(loading)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()
}

func (c *Crawler) fetchAndParseURLs(isHttps bool, domain string, urlString string, previousUrls map[string]bool) ([]string, error) {
	urls := make([]string, 0)
	urlSet := make(map[string]bool)

	originalURL := urlString
	outputDir := filepath.Join(c.outputDir, domain+"/")

	// Add http / https on prefix if not exists
	if !strings.HasPrefix(urlString, "http://") && !strings.HasPrefix(urlString, "https://") {
		if isHttps {
			urlString = "https://" + domain + urlString
		} else {
			urlString = "http://" + domain + urlString
		}
	}

	// Parse the URL and check its domain
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return urls, err
	}
	if parsedURL.Host != domain {
		return urls, nil
	}

	// Check if the url is already in the list
	if previousUrls[urlString] {
		return urls, nil
	} else {
		previousUrls[urlString] = true
	}

	// Create directories and check if the file already exists
	urlPath := parsedURL.Path
	filePath := filepath.Join(outputDir, urlPath)
	if strings.HasSuffix(parsedURL.Path, "/") || filepath.Ext(filePath) == "" {
		filePath = filepath.Join(filePath, "index")
	}
	if _, err := os.Stat(filePath); err == nil {
		return urls, nil
	}

	client := http.Client{
		Timeout:   time.Second * 10, // 10 seconds
		Transport: lib.HttpClientTransportSettings,
	}
	urlOnly := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	helper.InfoPrintln("[-] Fetching url: ", urlOnly)
	// Send a GET request to the website
	req, err := http.NewRequest("GET", urlOnly, nil)
	if err != nil {
		return urls, err
	}
	headers := http.Header{}
	headers.Set("User-Agent", lib.Config.Useragent)
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		return urls, err
	}

	defer resp.Body.Close()

	// Read the response content
	// Read the response content into a byte slice
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Create a new reader with the body bytes
	bodyReader := bytes.NewReader(bodyBytes)

	// Parse the response
	doc, err := goquery.NewDocumentFromReader(bodyReader)
	if err != nil {
		helper.ErrorPrintln("[!] Failed to read response body:", err)
		return urls, err
	}

	// Create directories and write the file
	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return nil, err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// Create a new reader with the body bytes again
	bodyReader = bytes.NewReader(bodyBytes)
	if _, err := io.Copy(file, bodyReader); err != nil { //TODO: no bytes
		return nil, err
	}

	// Crawl the response
	doc.Find("a[href], script[src], form[action]").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		src, _ := s.Attr("src")
		action, _ := s.Attr("action")

		if href != "" && href != originalURL && href != urlString && !urlSet[href] {
			urls = append(urls, href)
			urlSet[href] = true
		}
		if src != "" && !urlSet[src] {
			urls = append(urls, src)
			urlSet[src] = true
		}
		if action != "" && !urlSet[action] {
			urls = append(urls, action)
			urlSet[action] = true
		}
	})

	for _, newUrl := range urls {
		newUrls, err := c.fetchAndParseURLs(isHttps, domain, newUrl, previousUrls)
		if err == nil {
			urls = append(urls, newUrls...)
		} else {
			helper.ErrorPrintln("ERROR:", err)
		}
	}
	return urls, nil
}

func (c *Crawler) diffDirectories(domain, dir1, dir2 string) error {
	err := filepath.Walk(dir1, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(dir1, path)
			if err != nil {
				return err
			}

			pathInDir2 := filepath.Join(dir2, relPath)

			// Check if file exists in the second directory
			if _, err := os.Stat(pathInDir2); os.IsNotExist(err) {
				url := domain + "/" + relPath
				if strings.HasSuffix(url, "index") {
					url = url[:len(url)-6] // Remove "/index"
				}
				helper.ResultPrintln("[!] URL %s [%s] does not exist in %s\n", url, relPath, dir2)
				return nil
			}

			// Compare file contents
			content1, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var contentStr1 string
			contentStr1, err = c.prettyContent(path, content1)
			if err != nil {
				return err
			}

			content2, err := os.ReadFile(pathInDir2)
			if err != nil {
				return err
			}
			var contentStr2 string
			contentStr2, err = c.prettyContent(path, content2)
			if err != nil {
				return err
			}

			if contentStr1 != contentStr2 {
				helper.InfoPrintf("[+] File %s differs between directories\n", relPath)

				// Create directories and write the file
				filePath := filepath.Join(c.outputDir, domain+".diff", relPath)
				dirPath := filepath.Dir(filePath)
				if err := os.MkdirAll(dirPath, 0755); err != nil {
					return err
				}
				file, err := os.Create(filePath)
				if err != nil {
					return err
				}
				defer file.Close()

				dmp := diffmatchpatch.New()
				a, b, c := dmp.DiffLinesToChars(contentStr1, contentStr2)
				diffs := dmp.DiffMain(a, b, false)
				diffs = dmp.DiffCharsToLines(diffs, c)

				stringContent := make([]string, 0)
				for _, diff := range diffs {
					lines := strings.Split(diff.Text, "\n")
					for _, line := range lines {
						if line == "" {
							continue
						}
						switch diff.Type {
						case diffmatchpatch.DiffInsert:
							// log.Println("+", line)
							diffString := "+" + line
							fmt.Fprintf(file, "%s\n", diffString)
							stringContent = append(stringContent, diffString)
						case diffmatchpatch.DiffDelete:
							// log.Println("-", line)
							diffString := "-" + line
							fmt.Fprintf(file, "%s\n", diffString)
							stringContent = append(stringContent, diffString)
							// case diffmatchpatch.DiffEqual:
							// 	fmt.Println(" ", line)
							//  fmt.Fprintf(file, " %s\n", line)
						}
					}
				}

				// Secret scanning
				matchedFiles, err := localscan.StringArrayScanning(stringContent, path)
				if err != nil {
					helper.ErrorPrintln(err)
				} else {
					for _, matchedFile := range matchedFiles {
						helper.CustomizePrintln(matchedFile)
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (c *Crawler) prettyContent(path string, content []byte) (string, error) {
	var result string
	if strings.HasPrefix(string(content), "<!DOCTYPE html>") {
		var err error
		result, err = helper.PrettyHTML(content)
		if err != nil {
			return string(content), err
		}
	} else if strings.HasSuffix(path, ".js") {
		var err error
		result, err = helper.PrettyJS(content)
		if err != nil {
			return string(content), err
		}
	} else if strings.HasSuffix(path, ".json") {
		var err error
		result, err = helper.PrettyJson(content)
		if err != nil {
			return string(content), err
		}
	}
	return result, nil
}
