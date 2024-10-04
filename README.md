# OOTT - Offensive Operation and Threat Toolkit
OOTT suits for pentesters and for code reviewing
![demo](https://github.com/sebastian93921/oott/assets/4918219/a6e23db5-5e8c-4f2d-870a-084434ebbfe1)


# Usage Example
## Local file scanning
```
# Secrets scanning
./oott -localscan # Current directory
./oott -localscan -lp /tmp/
```
Feel free to contribute the `secretpatterns.json` file to enrich the secret scanning capability

## Sub-domain scanning
```
# Basic scanning
./oott -d example.com -subdomain-scan -fast-scan -http-status-scan

# Detailed scanning
./oott -d example.com -subdomain-scan

# Full subdomain scan with customize wordlist
./oott -d example.com -subdomain-scan -fast-scan -http-status-scan -wordlist /tmp/wordlist.txt
```

## Web scanning
```
# Basic scanning
./oott -d example.com -web-scan

# Web scan combine with subdomain scan
./oott -d example.com -subdomain-scan -fast-scan -http-status-scan -web-scan
```

## Secret scanning
```
./oott -d example.com -secret-scan -key-words test1,test2,test3,test4
```

## Email scanning
```
./oott -d example.com -email-scan
```

# Supported Plugins
| Catagories   | Plugines |
|:-------------|:-------------|
| Subdomain    | Brute forcing, HackerTarget, LeakIX, AlienVault, Archive.org, RapidDNS, Urlscan.io, MassDNS<sup>*2</sup>, CertSpotter, DuckDuckGo |
| Web scanning | Web Crawler<sup>*4</sup>, Wappalyzer<sup>*3</sup> |
| Secret       | Github<sup>*1</sup> |
| Email        | Email Format, PGP Scan, DuckDuckGo, Github<sup>*1</sup> |

<sup>*1</sup> An API key is necessary for access.  
<sup>*2</sup> Software installation is required.  
<sup>*3</sup> Does not support browser-like functionality.  
<sup>*4</sup> Features including files difference check.

# TODO


# Note
Run `golangci-lint run` before commit
