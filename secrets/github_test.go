package secrets

import (
	"encoding/json"
	"testing"
)

func testReadSecretPatterns() map[string]string {
	// Read patterns
	fileBytes, err := secretpatternsEmbed.ReadFile("secretpatterns.json")
	if err != nil {
		return nil
	}

	// Declare a map to hold the JSON data
	var keyAndRegex map[string]string

	// Unmarshal the JSON data into the map
	err = json.Unmarshal(fileBytes, &keyAndRegex)
	if err != nil {
		return nil
	}
	return keyAndRegex
}

func TestGithub_searchSecretsByPattern_SingleMatch(t *testing.T) {
	keyAndRegex := testReadSecretPatterns()
	type args struct {
		lines          []string
		repository     string
		path           string
		htmlURL        string
		searchPatterns map[string]string
	}

	tests := []struct {
		name string
		s    *Github
		args args
		want []SecretDetails
	}{
		{
			name: "Test case - ghp",
			s:    &Github{},
			args: args{
				lines: []string{
					"This is a test",
					"test key: ghp_testestesfdsvcxbvnyhtESFWFdsgvcdxvcRq",
					"line3",
				},
				repository:     "example/repo",
				path:           "/path/to/file",
				htmlURL:        "exmaple/repo",
				searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "test key: ghp_testestesfdsvcxbvnyhtESFWFdsgvcdxvcRq",
				},
			},
		},
		{
			name: "Test case - basic",
			s:    &Github{},
			args: args{
				lines: []string{
					"url = \"https://api.bamboohr.com/api/gateway.php/cxzvxwfew/v1/reports/\"+report_id+\"?format=csv&onlyCurrent=false\"",
					"",
					"headers = {\"authorization\": \"Basic HUIDXN32432jodsna18923uofdsfd5435fdsfsASDs=\"}",
				},
				repository:     "example/repo",
				path:           "/path/to/file",
				htmlURL:        "exmaple/repo",
				searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "headers = {\"authorization\": \"Basic HUIDXN32432jodsna18923uofdsfd5435fdsfsASDs=\"}",
				},
			},
		},
		// Add more test cases as needed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.searchSecretsByPattern(tt.args.lines, tt.args.repository, tt.args.path, tt.args.htmlURL, tt.args.searchPatterns); len(got) != 1 {
				t.Errorf("Github.searchSecretsByPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}
