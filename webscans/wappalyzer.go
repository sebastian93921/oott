package webscans

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"oott/helper"
	"oott/lib"

	"github.com/PuerkitoBio/goquery"
)

type Technology struct {
	Cats        []int                  `json:"cats"`
	Description string                 `json:"description"`
	Headers     map[string]string      `json:"headers"`
	Meta        map[string]interface{} `json:"meta"`
	HTML        interface{}            `json:"html"`
	Dom         interface{}            `json:"dom"`
	Icon        string                 `json:"icon"`
	Implies     interface{}            `json:"implies"`
	Js          map[string]string      `json:"js"`
	ScriptSrc   interface{}            `json:"scriptSrc"`
	Requires    interface{}            `json:"requires"`
	Website     string                 `json:"website"`
}

// Port Wappalyzer technology scanner database to go for regex scanning based on content
type Wappalyzer struct {
}

//go:embed wappalyzer/*.json
var embeddedWappalyzerFiles embed.FS

func (wp *Wappalyzer) downloadJSON(url, filePath string) ([]byte, error) {
	// Check if the file already exists
	if _, err := os.Stat(filePath); err == nil {
		helper.VerbosePrintf("[-] JSON file %s already exists. Skipping download.\n", filePath)
	} else {
		helper.InfoPrintf("[+] JSON file %s starts downloading.\n", filePath)
		response, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to download JSON: %s", response.Status)
		}

		file, err := os.Create(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		_, err = io.Copy(file, response.Body)
		if err != nil {
			return nil, err
		}

		helper.InfoPrintf("[+] JSON file %s downloaded successfully.\n", filePath)
	}

	// Read the downloaded JSON file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return fileBytes, nil
}

func (wp *Wappalyzer) ScanWebsites(domains []string) ([]WebsiteDetails, error) {
	baseURL := "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies/"

	// Map to store the technologies
	technologies := make(map[string]Technology)

	// Loop through the range of file names (_.json, a.json to z.json)
	for c := '_'; c <= 'z'; c++ {
		// Skip filenames before a.json
		if c < 'a' && c != '_' {
			continue
		}

		fileName := string(c) + ".json"
		url := baseURL + fileName

		data, err := wp.downloadJSON(url, lib.Config.Tmpfolder+fileName)
		if err != nil {
			helper.ErrorPrintf("[!] Error downloading JSON file %s. Read the default files... Error: %v\n", fileName, err)

			// Incase network issue, read local one
			data, err = embeddedWappalyzerFiles.ReadFile("wappalyzer/" + fileName)
			if err != nil {
				helper.ErrorPrintf("[!] Error reading embedded file:", err)
				return nil, err
			}
		}

		var temptechnologies map[string]Technology
		err = json.Unmarshal(data, &temptechnologies)
		if err != nil {
			helper.ErrorPrintf("[!] Error parsing JSON file %s: %v\n", fileName, err)
			return nil, err
		}

		helper.InfoPrintf("[+] JSON file %s loaded successfully.\n", fileName)

		// Add the technology to the map
		combineMaps(technologies, temptechnologies)
	}

	var websiteDetails []WebsiteDetails
	for _, domain := range domains {
		// HTTPS Scan
		url := "https://" + domain
		resultHttps, err := wp.scanWappalyzerScanByUrl(domain, url, technologies)
		if err != nil {
			helper.ErrorPrintln("[!] Error Scanning url: ", err)
		}

		// HTTP Scan
		url = "http://" + domain
		resultHttp, err := wp.scanWappalyzerScanByUrl(domain, url, technologies)
		if err != nil {
			helper.ErrorPrintln("[!] Error Scanning url: ", err)
		}

		if resultHttps.DomainName != "" {
			resultHttps.Technologies = wp.appendDistinct(resultHttps.Technologies, resultHttp.Technologies)
		} else if resultHttp.DomainName != "" {
			// No result on https, just use it to append the result
			resultHttps = resultHttp
		} else {
			// No result
			continue
		}

		resultHttps.Source = "Wappalyzer"
		websiteDetails = append(websiteDetails, resultHttps)
	}

	return websiteDetails, nil
}

func (wp *Wappalyzer) scanWappalyzerScanByUrl(domain string, url string, technologies map[string]Technology) (WebsiteDetails, error) {
	client := http.Client{
		Timeout: time.Second * 2,
	}

	result := WebsiteDetails{}
	// Send a GET request to the website
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result, err
	}
	headers := http.Header{}
	headers.Set("User-Agent", lib.Config.Useragent)
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	// Read the response content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response body:", err)
		return result, err
	}
	content := string(body)

	// Suffle technologies
	technologies = wp.suffleTechnologiesMap(technologies)

	// Search for technologies based on HTML regex or script source
	for name, tech := range technologies {
		searched := false

		// Check if the headers regex matches the content
		if tech.Headers != nil {
			for header, expectedValue := range tech.Headers {
				actualValue := resp.Header.Get(header)
				if expectedValue == "" && actualValue != "" {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] header static matched for technology: %s\n", domain, name)
					helper.VerbosePrintln(header, "->", actualValue)

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, nil)
					searched = true
					continue
				} else if expectedValue != "" {

					matches, err := wp.matchingWithModification(expectedValue, actualValue)
					if err != nil {
						helper.ErrorPrintf("[!] Error matching header regex for technology %s: %v\n", name, err)
						continue
					}
					if len(matches) > 0 {
						helper.InfoPrintf("[Wappalyzer] Domain [%s] header regex matched for technology: %s\n", domain, name)
						helper.VerbosePrintln(expectedValue, "->", matches)

						result.DomainName = domain
						result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
						searched = true
						continue
					}
				}
			}
		}

		// Check if the Meta regex matches the content
		if tech.Meta != nil {
			// Create a reader from the byte array
			reader := bytes.NewReader(body)

			// Parse the HTML document
			doc, err := goquery.NewDocumentFromReader(reader)
			if err != nil {
				helper.ErrorPrintf("[!] Error perform meta search %s: %v\n", name, err)
				continue
			}

			for metaName, metaValue := range tech.Meta {
				switch regexv := metaValue.(type) {
				case string:
					selector := fmt.Sprintf(`meta[name="%s"]`, metaName)
					doc.Find(selector).Each(func(i int, s *goquery.Selection) {
						content := s.AttrOr("content", "")
						matches, err := wp.matchingWithModification(regexv, content)
						if err != nil {
							helper.ErrorPrintf("[!] Error matching Meta regex for technology %s: %v\n", name, err)
						}
						if len(matches) > 0 {
							helper.InfoPrintf("[Wappalyzer] Domain [%s] Meta regex matched for technology: %s\n", domain, name)
							helper.VerbosePrintln(regexv, "->", matches)

							result.DomainName = domain
							result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
							searched = true
						}
					})
				case []string:
					for _, value := range regexv {
						selector := fmt.Sprintf(`meta[name="%s"]`, metaName)
						doc.Find(selector).Each(func(i int, s *goquery.Selection) {
							content := s.AttrOr("content", "")
							matches, err := wp.matchingWithModification(value, content)
							if err != nil {
								helper.ErrorPrintf("[!] Error matching Meta regex for technology %s: %v\n", name, err)
							}
							if len(matches) > 0 {
								helper.InfoPrintf("[Wappalyzer] Domain [%s] Meta regex matched for technology: %s\n", domain, name)
								helper.VerbosePrintln(value, "->", matches)

								result.DomainName = domain
								result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
								searched = true
							}
						})
					}
				}
			}
		}

		// Check if the HTML regex matches the content
		if tech.HTML != nil {
			switch html := tech.HTML.(type) {
			case string:
				matches, err := wp.matchingWithModification(html, content)
				if err != nil {
					helper.ErrorPrintf("[!] Error matching HTML regex for technology %s: %v\n", name, err)
					continue
				}
				if len(matches) > 0 {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] HTML regex matched for technology: %s\n", domain, name)
					helper.VerbosePrintln(html, "->", matches)

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
					searched = true
				}
			case []string:
				for _, s := range html {
					matches, err := wp.matchingWithModification(s, content)
					if err != nil {
						helper.ErrorPrintf("[!] Error matching HTML regex for technology %s: %v\n", name, err)
						continue
					}
					if len(matches) > 0 {
						helper.InfoPrintf("[Wappalyzer] Domain [%s] HTML regex matched for technology: %s\n", domain, name)
						helper.VerbosePrintln(s, "->", matches)

						result.DomainName = domain
						result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
						searched = true
					}
				}
			}
		}

		// Check if the script source matches the content
		if tech.HTML != nil {
			switch src := tech.ScriptSrc.(type) {
			case string:
				matches, err := wp.matchingWithModification(src, content)
				if err != nil {
					helper.ErrorPrintf("[!] Error matching script source regex for technology %s: %v\n", name, err)
					continue
				}
				if len(matches) > 0 {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] Script source regex matched for technology: %s\n", domain, name)
					helper.VerbosePrintln(src, "->", matches)

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
					searched = true
				}
			case []string:
				for _, s := range src {
					matches, err := wp.matchingWithModification(s, content)
					if err != nil {
						helper.ErrorPrintf("[!] Error matching script source regex for technology %s: %v\n", name, err)
						continue
					}
					if len(matches) > 0 {
						helper.InfoPrintf("[Wappalyzer] Domain [%s] Script source regex matched for technology: %s\n", domain, name)
						helper.VerbosePrintln(s, "->", matches)

						result.DomainName = domain
						result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
						searched = true
					}
				}
			}
		}

		// Dom search
		if tech.Dom != nil {
			// Create a reader from the byte array
			reader := bytes.NewReader(body)

			// Parse the HTML document
			doc, err := goquery.NewDocumentFromReader(reader)
			if err != nil {
				helper.ErrorPrintf("[!] Error perform dom search %s: %v\n", name, err)
				continue
			}

			switch dom := tech.Dom.(type) {
			case string:
				elements := doc.Find(dom)

				if elements.Length() > 0 {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] Dom search matched for technology: %s\n", domain, name)
					if lib.Config.VerboseMode {
						elements.Each(func(i int, element *goquery.Selection) {
							for _, node := range element.Nodes {
								helper.VerbosePrintln(node)
							}
						})
					}

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, nil)
					searched = true
				}
			case []string:
				for _, s := range dom {
					elements := doc.Find(s)

					if elements.Length() > 0 {
						helper.InfoPrintf("[Wappalyzer] Domain [%s] Dom search matched for technology: %s\n", domain, name)
						if lib.Config.VerboseMode {
							elements.Each(func(i int, element *goquery.Selection) {
								for _, node := range element.Nodes {
									helper.VerbosePrintln(node)
								}
							})
						}

						result.DomainName = domain
						result.Technologies = wp.appendToTechnology(result.Technologies, name, nil)
						searched = true
					}
				}
			}
		}

		// Add others items
		if searched {
			// Required items
			switch requires := tech.Requires.(type) {
			case string:
				result.Technologies = wp.appendToTechnology(result.Technologies, requires, nil)
			case []string:
				for _, s := range requires {
					result.Technologies = wp.appendToTechnology(result.Technologies, s, nil)
				}
			}
			// Implies items
			switch implies := tech.Implies.(type) {
			case string:
				result.Technologies = wp.appendToTechnology(result.Technologies, implies, nil)
			case []string:
				for _, s := range implies {
					result.Technologies = wp.appendToTechnology(result.Technologies, s, nil)
				}
			}
		}
	}

	return result, nil
}

func (wp *Wappalyzer) suffleTechnologiesMap(technologies map[string]Technology) map[string]Technology {
	// Extract keys into a slice and shuffle the slice
	keys := make([]string, 0, len(technologies))
	for key := range technologies {
		keys = append(keys, key)
	}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	rand.Shuffle(len(keys), func(i, j int) {
		keys[i], keys[j] = keys[j], keys[i]
	})

	// Create a temporary slice to store the shuffled values
	shuffledValues := make([]Technology, 0, len(technologies))
	for _, key := range keys {
		shuffledValues = append(shuffledValues, technologies[key])
	}

	// Assign the shuffled values back into the map
	for i, key := range keys {
		technologies[key] = shuffledValues[i]
	}

	return technologies
}

func (wp *Wappalyzer) appendToTechnology(websiteDetailTechnology []WebsiteDetailTechnology, technologyName string, matchesResults []string) []WebsiteDetailTechnology {
	newWebsiteDetailTechnology := WebsiteDetailTechnology{
		Name: technologyName,
	}

	for _, tech := range websiteDetailTechnology {
		if tech.Name == technologyName && tech.Version != "" {
			// Already exist
			return websiteDetailTechnology
		} else if tech.Name == technologyName {
			newWebsiteDetailTechnology.Version = tech.Version
			break
		}
	}

	// Try to add version into the technology
	if matchesResults != nil && len(matchesResults) > 1 {
		newWebsiteDetailTechnology.Version = matchesResults[1]
	}

	websiteDetailTechnology = append(websiteDetailTechnology, newWebsiteDetailTechnology)
	return websiteDetailTechnology
}

func (wp *Wappalyzer) matchingWithModification(pattern string, content string) (matchesResults []string, err error) {
	// Go didn't support match group version \1 \2 \3, need to remove it (Tags (a non-standard syntax))
	// Remove the \;version: and anything after its
	parts := strings.Split(pattern, "\\;version:\\")
	pattern = parts[0]
	parts = strings.Split(pattern, "\\;confidence:")
	pattern = parts[0]

	// Compile the regex pattern
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Find submatch
	submatches := regex.FindStringSubmatch(content)

	// Remove empty of only have spaces
	var result []string
	for _, s := range submatches {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			result = append(result, s)
		}
	}

	// Debug use
	if strings.Contains(pattern, "version") && len(result) > 0 && lib.Config.VerboseMode {
		helper.VerbosePrintln("[-] Regex contains version check [", pattern, "] > ", result)
	}
	return result, nil
}

func (wp *Wappalyzer) appendDistinct(dest, src []WebsiteDetailTechnology) []WebsiteDetailTechnology {
	var temp []WebsiteDetailTechnology

	// Create a map to track the existing technologies in the destination list
	existing := make(map[string]WebsiteDetailTechnology)
	for _, tech := range dest {
		// Skip the technology if it already exists in the destination list
		if _, found := existing[tech.Name]; found {
			continue
		}

		// Update the existing technology with a version from the source list
		for _, srcTech := range src {
			if srcTech.Name == tech.Name && srcTech.Version != "" {
				tech.Version = srcTech.Version
				break
			}
		}

		// Append the distinct technology to the destination list
		temp = append(temp, tech)
		existing[tech.Name] = tech
	}

	for _, tech := range src {
		// Skip the technology if it already exists in the destination list
		if _, found := existing[tech.Name]; found {
			continue
		}

		// Update the existing technology with a version from the source list
		for _, srcTech := range dest {
			if srcTech.Name == tech.Name && srcTech.Version != "" {
				tech.Version = srcTech.Version
				break
			}
		}

		// Append the distinct technology to the destination list
		temp = append(temp, tech)
		existing[tech.Name] = tech
	}

	return temp
}

func combineMaps(map1, map2 map[string]Technology) {
	for key, value := range map2 {
		map1[key] = value
	}
}
