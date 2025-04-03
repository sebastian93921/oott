package webscans

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"oott/defaults"
	"oott/helper"
	"oott/lib"

	"github.com/PuerkitoBio/goquery"
)

type Technology struct {
	Cats        []int                  `json:"cats"`
	Description string                 `json:"description"`
	Headers     map[string]string      `json:"headers"`
	Meta        map[string]interface{} `json:"meta"`
	Text        interface{}            `json:"text"`
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

func (wp *Wappalyzer) scanContent(domain string, content []byte, technologies map[string]Technology, headers http.Header) (WebsiteDetails, error) {
	helper.InfoPrintln("[Wappalyzer] Start scanning content for domain:", domain)

	result := WebsiteDetails{}
	contentStr := string(content)

	// Suffle technologies
	technologies = wp.suffleTechnologiesMap(technologies)

	// Search for technologies based on HTML regex or script source
	for name, tech := range technologies {
		searched := false

		// Check if the headers regex matches the content
		if tech.Headers != nil && headers != nil {
			for header, expectedValue := range tech.Headers {
				actualValue := headers.Get(header)
				if expectedValue == "" && actualValue != "" {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] header static matched for technology: %s\n", domain, name)
					helper.VerbosePrintln(header, "->", actualValue)

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, nil)
					searched = true
				} else if expectedValue != "" {
					matches, err := wp.matchingWithModification(expectedValue, actualValue)
					if err != nil {
						helper.ErrorPrintf("[!] Error matching header regex for technology %s: %v\n", name, err)
						helper.VerbosePrintln("[ERR > ]", expectedValue)
					}
					if len(matches) > 0 {
						helper.InfoPrintf("[Wappalyzer] Domain [%s] header regex matched for technology: %s\n", domain, name)
						helper.VerbosePrintln(expectedValue, "->", matches)

						result.DomainName = domain
						result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
						searched = true
					}
				}
			}
		}

		// Check if the Meta regex matches the content
		if tech.Meta != nil {
			// Create a reader from the byte array
			reader := bytes.NewReader(content)

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
							helper.VerbosePrintln("[ERR > ]", regexv)
						}
						if len(matches) > 0 {
							helper.InfoPrintf("[Wappalyzer] Domain [%s] Meta regex matched for technology: %s\n", domain, name)
							helper.VerbosePrintln(regexv, "->", matches)

							result.DomainName = domain
							result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
							searched = true
						}
					})
				case []interface{}:
					for _, value := range regexv {
						selector := fmt.Sprintf(`meta[name="%s"]`, metaName)
						doc.Find(selector).Each(func(i int, s *goquery.Selection) {
							content := s.AttrOr("content", "")

							converted := fmt.Sprint(value)
							matches, err := wp.matchingWithModification(converted, content)
							if err != nil {
								helper.ErrorPrintf("[!] Error matching Meta regex for technology %s: %v\n", name, err)
								helper.VerbosePrintln("[ERR > ]", value)
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
			result := wp.processSearchByInterface("HTML regex", name, domain, contentStr, &result, tech.HTML)
			if result {
				searched = true
			}
		}

		// Check if the script source matches the content
		if tech.ScriptSrc != nil {
			result := wp.processSearchByInterface("Script source regex", name, domain, contentStr, &result, tech.ScriptSrc)
			if result {
				searched = true
			}
		}

		// Check if the text matches the content
		if tech.Text != nil {
			result := wp.processSearchByInterface("Text regex", name, domain, contentStr, &result, tech.Text)
			if result {
				searched = true
			}
		}

		// Dom search
		if tech.Dom != nil {
			// Create a reader from the byte array
			reader := bytes.NewReader(content)

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
			case []interface{}:
				for _, s := range dom {
					converted := fmt.Sprint(s)
					elements := doc.Find(converted)

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
			case map[string]interface{}:
				for key, val := range dom {
					elements := doc.Find(key)
					if elements.Length() > 0 {
						result := wp.processDomElements(name, domain, &result, val, elements)
						if result {
							searched = true
						}
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
			case []interface{}:
				for _, s := range requires {
					converted := fmt.Sprint(s)
					result.Technologies = wp.appendToTechnology(result.Technologies, converted, nil)
				}
			}
			// Implies items
			switch implies := tech.Implies.(type) {
			case string:
				result.Technologies = wp.appendToTechnology(result.Technologies, implies, nil)
			case []interface{}:
				for _, s := range implies {
					converted := fmt.Sprint(s)
					result.Technologies = wp.appendToTechnology(result.Technologies, converted, nil)
				}
			}
		}
	}

	return result, nil
}

func (wp *Wappalyzer) scanWappalyzerScanByLocalFile(domain string, filePath string, technologies map[string]Technology) (WebsiteDetails, error) {
	helper.InfoPrintln("[Wappalyzer] Start scanning local file:", filePath)

	// Read the file content
	body, err := os.ReadFile(filePath)
	if err != nil {
		helper.ErrorPrintln("[!] Failed to read file:", err)
		return WebsiteDetails{}, err
	}

	return wp.scanContent(domain, body, technologies, nil)
}

func (wp *Wappalyzer) scanWappalyzerScanByUrl(domain string, urlStr string, technologies map[string]Technology) (WebsiteDetails, error) {
	helper.InfoPrintln("[Wappalyzer] Start scanning URL:", urlStr)

	// Extract domain name from URL if not already provided
	if domain == "" {
		parsedURL, err := url.Parse(urlStr)
		if err == nil {
			domain = parsedURL.Host
		}
	}

	client := http.Client{
		Timeout:   time.Second * 10, // 10 seconds
		Transport: lib.HttpClientTransportSettings,
	}

	// Send a GET request to the website
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return WebsiteDetails{}, err
	}
	headers := http.Header{}
	headers.Set("User-Agent", lib.Config.Useragent)
	req.Header = headers

	resp, err := client.Do(req)
	if err != nil {
		return WebsiteDetails{}, err
	}

	defer resp.Body.Close()

	// Read the response content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		helper.ErrorPrintln("[!] Failed to read response body:", err)
		return WebsiteDetails{}, err
	}

	result, err := wp.scanContent(domain, body, technologies, resp.Header)
	if err != nil {
		return result, err
	}

	// Assign status code to result
	result.StatusCode = strconv.Itoa(resp.StatusCode)
	return result, nil
}

func (wp *Wappalyzer) processSearchByInterface(methodName, name, domain, content string, result *WebsiteDetails, source interface{}) bool {
	searched := false
	switch src := source.(type) {
	case string:
		matches, err := wp.matchingWithModification(src, content)
		if err != nil {
			helper.ErrorPrintf("[!] Error matching %s for technology %s: %v\n", methodName, name, err)
			helper.VerbosePrintln("[ERR > ]", src)
		}
		if len(matches) > 0 {
			helper.InfoPrintf("[Wappalyzer] Domain [%s] %s matched for technology: %s\n", domain, methodName, name)
			helper.VerbosePrintln(src, "->", matches)

			result.DomainName = domain
			result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
			searched = true
		}
	case []interface{}:
		for _, s := range src {
			converted := fmt.Sprint(s)
			matches, err := wp.matchingWithModification(converted, content)
			if err != nil {
				helper.ErrorPrintf("[!] Error matching %s for technology %s: %v\n", methodName, name, err)
				helper.VerbosePrintln("[ERR > ]", s)
			}
			if len(matches) > 0 {
				helper.InfoPrintf("[Wappalyzer] Domain [%s] %s matched for technology: %s\n", domain, methodName, name)
				helper.VerbosePrintln(s, "->", matches)

				result.DomainName = domain
				result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)
				searched = true
			}
		}
	}

	return searched
}

func (wp *Wappalyzer) processDomElements(name string, domain string, result *WebsiteDetails, value interface{}, elements *goquery.Selection) bool {
	searched := false
	switch subValue := value.(type) {
	case map[string]interface{}:
		for elekey, eleval := range subValue {
			switch eleType := eleval.(type) {
			case map[string]interface{}:
				if elekey == "attributes" || elekey == "text" {
					searched = wp.processDomElements(name, domain, result, eleval, elements)
				}
				elements = elements.Find(elekey)
				if elements.Length() > 0 {
					searched = wp.processDomElements(name, domain, result, eleval, elements)
				}
			case string:
				if elekey == "exists" {
					helper.InfoPrintf("[Wappalyzer] Domain [%s] Dom search exists for technology: %s\n", domain, name)

					// Debug log
					if lib.Config.VerboseMode {
						helper.VerbosePrintln("Dom Key:", elekey, "=", eleType)
						elements.Each(func(i int, element *goquery.Selection) {
							for _, node := range element.Nodes {
								helper.VerbosePrintln(node)
							}
						})
					}

					result.DomainName = domain
					result.Technologies = wp.appendToTechnology(result.Technologies, name, nil)

					// Stop searching
					searched = true
				} else if elekey == "text" {
					// Text search
					result := wp.processSearchByInterface("Dom text regex", name, domain, elements.Text(), result, eleval)
					if result {
						searched = true
					}
				} else {
					// Attributes search
					elements.Each(func(_ int, s *goquery.Selection) {
						for _, attr := range s.Nodes[0].Attr {
							if elekey == attr.Key {
								matches, err := wp.matchingWithModification(eleType, attr.Val)
								if err != nil {
									helper.ErrorPrintf("[!] Error matching Dom sub regex search for technology %s: %v\n", name, err)
									helper.VerbosePrintln("[ERR > ]", s)
								}
								if len(matches) > 0 {
									helper.InfoPrintf("[Wappalyzer] Domain [%s] Dom sub regex match for technology: %s\n", domain, name)
									helper.VerbosePrintln("Dom Key:", elekey, "=", eleType, "->", matches)

									result.DomainName = domain
									result.Technologies = wp.appendToTechnology(result.Technologies, name, matches)

									// Stop searching
									searched = true
									return
								}
							}
						}
					})
				}
			default:
				return searched
			}
		}
	default:
		return searched
	}
	return searched
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

	// Try to add version into the technology
	if len(matchesResults) > 1 {
		newWebsiteDetailTechnology.Version = matchesResults[1]
	}

	indexToDelete := -1
	for i, tech := range websiteDetailTechnology {
		if tech.Name == technologyName && tech.Version != "" {
			// Already exist
			return websiteDetailTechnology
		} else if tech.Name == technologyName && tech.Version == "" && newWebsiteDetailTechnology.Version == "" {
			// Already exist and no updates
			return websiteDetailTechnology
		} else if tech.Name == technologyName {
			newWebsiteDetailTechnology.Version = tech.Version
			indexToDelete = i
			break
		}
	}

	if indexToDelete != -1 {
		websiteDetailTechnology = append(websiteDetailTechnology[:indexToDelete], websiteDetailTechnology[indexToDelete+1:]...)
	}

	websiteDetailTechnology = append(websiteDetailTechnology, newWebsiteDetailTechnology)
	return websiteDetailTechnology
}

func (wp *Wappalyzer) matchingWithModification(pattern string, content string) (matchesResults []string, err error) {
	var negativeLookAroundRegex []string

	// Go didn't support match group version \1 \2 \3, need to remove it (Tags (a non-standard syntax))
	// Remove the \;version: and anything after its
	parts := strings.Split(pattern, "\\;version:")
	pattern = parts[0]
	parts = strings.Split(pattern, "\\;confidence:")
	pattern = parts[0]

	// This one first
	negativeLookaheadRegex := `\(\?!\(.*?\)\/\)`
	negativeLookaheadMatches := regexp.MustCompile(negativeLookaheadRegex).FindAllString(pattern, -1)
	if len(negativeLookaheadMatches) > 0 {
		for _, val := range negativeLookaheadMatches {
			tmp := strings.ReplaceAll(val, "(?!(", "(")
			tmp = strings.ReplaceAll(tmp, ")/)", ")")
			negativeLookAroundRegex = append(negativeLookAroundRegex, tmp)
			pattern = strings.Replace(pattern, val, "", 1)
		}
	}
	// This after
	negativeLookaheadRegex = `\(\?!.*?\)`
	negativeLookaheadMatches = regexp.MustCompile(negativeLookaheadRegex).FindAllString(pattern, -1)
	if len(negativeLookaheadMatches) > 0 {
		for _, val := range negativeLookaheadMatches {
			negativeLookAroundRegex = append(negativeLookAroundRegex, strings.ReplaceAll(val, "(?!", "("))
			pattern = strings.Replace(pattern, val, "", 1)
		}
	}

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
		if len(negativeLookAroundRegex) > 0 {
			for _, negativeLookPattern := range negativeLookAroundRegex {
				// Compile the regex pattern
				negRegex, err := regexp.Compile(negativeLookPattern)
				if err != nil {
					return nil, err
				}
				match := negRegex.FindString(s)
				if match != "" {
					helper.VerbosePrintln("[-] Negative lookup found:", s, " .Pattern:", negativeLookPattern)
					s = ""
				}
			}
		}
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

func (wp *Wappalyzer) ScanWebsites(domains []string) ([]WebsiteDetails, error) {
	// baseURL := "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies/" # wappalyzer went private in August 2023
	baseURL := "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/"
	skipDownload := false

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

		var data []byte
		var err error
		if !skipDownload {
			data, err = wp.downloadJSON(url, lib.Config.Tmpfolder+fileName)
			if err != nil {
				helper.ErrorPrintf("[!] Error downloading JSON file %s. Read the default files... Error: %v\n", fileName, err)

				// Incase network issue, read local one
				data, err = defaults.EmbeddedWappalyzerFiles.ReadFile("wappalyzer/" + fileName)
				if err != nil {
					helper.ErrorPrintf("[!] Error reading embedded file:", err)
					return nil, err
				}
				skipDownload = true
			}
		} else {
			data, err = defaults.EmbeddedWappalyzerFiles.ReadFile("wappalyzer/" + fileName)
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

		// Add the technology to the map
		combineMaps(technologies, temptechnologies)
	}

	var websiteDetails []WebsiteDetails

	// Read domains from last-fetched-domains.txt if it exists
	domainsPath := filepath.Join(lib.Config.Tmpfolder, "result/crawler/websites/last-fetched-domains.txt")
	if _, err := os.Stat(domainsPath); err == nil {
		// Read domains from file
		domainsData, err := os.ReadFile(domainsPath)
		if err == nil {
			// Split into lines and add to domains list
			discoveredDomains := strings.Split(string(domainsData), "\n")
			for _, domain := range discoveredDomains {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					domains = append(domains, domain)
				}
			}
		}
	}

	// Remove duplicates from domains
	uniqueDomains := make(map[string]bool)
	var cleanDomains []string
	for _, domain := range domains {
		if !uniqueDomains[domain] {
			uniqueDomains[domain] = true
			cleanDomains = append(cleanDomains, domain)
		}
	}

	for _, domain := range cleanDomains {
		// Try to scan local file first
		localFilePath := filepath.Join(lib.Config.Tmpfolder, "result/crawler/websites", domain, "index")
		if _, err := os.Stat(localFilePath); err == nil {
			result, err := wp.scanWappalyzerScanByLocalFile(domain, localFilePath, technologies)
			if err != nil {
				helper.ErrorPrintln("[!] Error scanning local file:", err)
			} else if result.DomainName != "" {
				result.Source = "Wappalyzer"
				websiteDetails = append(websiteDetails, result)
			}
		}

		// If local file scan fails or file doesn't exist, fall back to HTTP requests
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
