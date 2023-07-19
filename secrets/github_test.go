package secrets

import (
	"encoding/json"
	"oott/defaults"
	"testing"
)

func testReadSecretPatterns() map[string]string {
	// Read patterns
	fileBytes, err := defaults.SecretpatternsEmbed.ReadFile("secretpatterns.json")
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

func TestGithub_searchSecretsByPattern_Test(t *testing.T) {
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
			name: "Test case - private pgp key",
			s:    &Github{},
			args: args{
				lines: []string{
					"APPLE_CLIENT_ID=com.vaib.only.web",
					"APPLE_TEAM_ID=XF5KBAKJ2F",
					"APPLE_KEY_ID=NCHD3VR2V6",
					"APPLE_KEY=-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PGP PRIVATE KEY BLOCK-----",
					"APPLE_CALLBACK_URL=https://dev-gateway.ovstg.click/auth/apple/callback",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "APPLE_KEY=-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PGP PRIVATE KEY BLOCK-----",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.searchSecretsByPattern(tt.args.lines, tt.args.repository, tt.args.path, tt.args.htmlURL, tt.args.searchPatterns); len(got) != len(tt.want) {
				t.Errorf("Github.searchSecretsByPattern() = %v, want %v", got, tt.want)
			}
		})
	}
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
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
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
					"url = \"https://api.testtest.com/api/gateway.php/cxzvxwfew/v1/reports/\"+report_id+\"?format=csv&onlyCurrent=false\"",
					"",
					"headers = {\"authorization\": \"Basic AQENVg688MSGlEgdOJpjIUC=\"}",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "headers = {\"authorization\": \"Basic AQENVg688MSGlEgdOJpjIUC=\"}",
				},
			},
		},
		{
			name: "Test case - Simple password",
			s:    &Github{},
			args: args{
				lines: []string{
					"conn = psycopg2.connect(",
					"	host=\"127.0.0.1\",",
					"	port=\"2000\",",
					"	database=\"hrta\",",
					"	user=\"app_hrta\",",
					"	password=\"Vi0Tm1G4OvzslaIyESL9\"",
					")",
					"dwh = conn.cursor()",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "Username and password in file",
					Content:     "password=\"Vi0Tm1G4OvzslaIyESL9\"",
				},
			},
		},
		{
			name: "Test case - Bearer token",
			s:    &Github{},
			args: args{
				lines: []string{
					"headers = {",
					"	'Accept': 'application/vnd.heroku+json; version=3',",
					"	'Authorization': f'Bearer eyJhbGciOiJIUzI1NiasInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI5YjQ2MDY0MC1bfwIyLTQzY2YtOGM3Ni0xYjQyZGVjNTU5NjQiLCJpYXQiOjE2ODY2NTAwMDQsImV4cCI6MTY4NjczNjQwNH0.DIkikc6lQigHFBxdfdbWLmsJwMnxr4hLJtKB9I-UHpE'",
					"}",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "Bearer Authentication Token",
					Content:     "'Authorization': f'Bearer eyJhbGciOiJIUzI1NiasInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI5YjQ2MDY0MC1bfwIyLTQzY2YtOGM3Ni0xYjQyZGVjNTU5NjQiLCJpYXQiOjE2ODY2NTAwMDQsImV4cCI6MTY4NjczNjQwNH0.DIkikc6lQigHFBxdfdbWLmsJwMnxr4hLJtKB9I-UHpE'",
				},
			},
		},
		{
			name: "Test case - secret",
			s:    &Github{},
			args: args{
				lines: []string{
					"JwtModule.register({",
					"	global: true,",
					"	// secret: jwtConstants.secret,",
					"	secret: 'NarwhalxxxpiBinturongWoollyMaxxxthThylacinePangolin',",
					"	signOptions: { expiresIn: JWT_EXPIRES_IN },",
					"}),",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "Bearer Authentication Token",
					Content:     "secret: 'NarwhalxxxpiBinturongWoollyMaxxxthThylacinePangolin',",
				},
			},
		},
		{
			name: "Test case - private key",
			s:    &Github{},
			args: args{
				lines: []string{
					"APPLE_CLIENT_ID=com.vaib.only.web",
					"APPLE_TEAM_ID=XF5KBAKJ2F",
					"APPLE_KEY_ID=NCHD3VR2V6",
					"APPLE_KEY=-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PRIVATE KEY-----",
					"APPLE_CALLBACK_URL=https://dev-gateway.ovstg.click/auth/apple/callback",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "APPLE_KEY=-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PRIVATE KEY-----",
				},
			},
		},
		{
			name: "Test case - private pgp key",
			s:    &Github{},
			args: args{
				lines: []string{
					"APPLE_CLIENT_ID=com.vaib.only.web",
					"APPLE_TEAM_ID=XF5KBAKJ2F",
					"APPLE_KEY_ID=NCHD3VR2V6",
					"APPLE_KEY=-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PGP PRIVATE KEY BLOCK-----",
					"APPLE_CALLBACK_URL=https://dev-gateway.ovstg.click/auth/apple/callback",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "GitHub Token",
					Content:     "APPLE_KEY=-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIGTAgEAMBMGByqbgtgtbAgEGCCqGSM49AwEHBHkwdwIBAQQgCSc1wF+mLoQ3wk3y\nW/JvBMB6Z2q1uQn3pSEnmAXF8HzzCgYIKoZIzj0DAQehRANCAASb+bW9Ohikp+ra\njOswnXE/wMezc46Lg8q085s4qjlZrnHELYZSVuzz/Xuh8h6Cn5f2szz9os4OO3Bt\nP37NIwJn\n-----END PGP PRIVATE KEY BLOCK-----",
				},
			},
		},
		{
			name: "Test case - false positive aws token",
			s:    &Github{},
			args: args{
				lines: []string{
					"##===========================================================================================================",
					"# 					Test test test test  ",
				},
				repository: "example/repo", path: "/path/to/file", htmlURL: "exmaple/repo", searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{},
		},
		// Add more test cases as needed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.searchSecretsByPattern(tt.args.lines, tt.args.repository, tt.args.path, tt.args.htmlURL, tt.args.searchPatterns); len(got) != len(tt.want) {
				t.Errorf("Github.searchSecretsByPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGithub_searchSecretsByPattern_MoreThenOneMatch(t *testing.T) {
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
			name: "Test case - WP-Config",
			s:    &Github{},
			args: args{
				lines: []string{
					"<?php",
					"",
					"define( 'DB_NAME', 'database_name' );",
					"define( 'DB_USER', 'database_user' );",
					"define( 'DB_PASSWORD', 'your_password' );",
					"define( 'DB_HOST', 'localhost' );",
					"define( 'DB_CHARSET', 'utf8mb4' );",
					"define( 'DB_COLLATE', '' );",
					"",
					"$table_prefix = 'wp_';",
					"",
					"define( 'AUTH_KEY', 'your_auth_key' );",
					"define( 'SECURE_AUTH_KEY', 'your_secure_auth_key' );",
					"define( 'LOGGED_IN_KEY', 'your_logged_in_key' );",
					"define( 'NONCE_KEY', 'your_nonce_key' );",
					"define( 'AUTH_SALT', 'your_auth_salt' );",
					"define( 'SECURE_AUTH_SALT', 'your_secure_auth_salt' );",
					"define( 'LOGGED_IN_SALT', 'your_logged_in_salt' );",
					"define( 'NONCE_SALT', 'your_nonce_salt' );",
					"",
					"define( 'WP_DEBUG', false );",
					"",
					"/* That's all, stop editing! Happy publishing. */",
					"",
				},
				repository:     "example/repo",
				path:           "/path/to/file",
				htmlURL:        "exmaple/repo",
				searchPatterns: keyAndRegex,
			},
			want: []SecretDetails{
				{
					PatternName: "WP-Config",
					Content:     "define( 'DB_PASSWORD', 'your_password' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'AUTH_KEY', 'your_auth_key' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'SECURE_AUTH_KEY', 'your_secure_auth_key' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'LOGGED_IN_KEY', 'your_logged_in_key' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'NONCE_KEY', 'your_nonce_key' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'AUTH_SALT', 'your_auth_salt' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'SECURE_AUTH_SALT', 'your_secure_auth_salt' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'LOGGED_IN_SALT', 'your_logged_in_salt' );",
				},
				{
					PatternName: "WP-Config",
					Content:     "define( 'NONCE_SALT', 'your_nonce_salt' );",
				},
			},
		},
		// Add more test cases as needed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.searchSecretsByPattern(tt.args.lines, tt.args.repository, tt.args.path, tt.args.htmlURL, tt.args.searchPatterns); len(got) != len(tt.want) {
				t.Errorf("Github.searchSecretsByPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}
