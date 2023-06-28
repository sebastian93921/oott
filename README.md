# OOTT - OSINT Offensive Toolkit
Note: This application only works on UNIX / LINUX like operating system

# Usage Example
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
Timeout period is 10 seconds.
```
# Basic scanning
./oott -d example.com -web-scan

# Web scan combine with subdomain scan
./oott -d example.com -subdomain-scan -fast-scan -http-status-scan
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
| Subdomain    | HackerTarget, LeakIX, AlienVault, Archive.org, RapidDNS, Urlscan.io, MassDNS<sup>*2</sup>, Brute forcing, CertSpotter, DuckDuckGo |
| Web scanning | Wappalyzer<sup>*3</sup> |
| Secret       | Github<sup>*1</sup> |
| Email        | Email Format, PGP Scan, DuckDuckGo, Github<sup>*1</sup> |

<sup>*1</sup> An API key is necessary for access.  
<sup>*2</sup> Software installation is required.  
<sup>*3</sup> Does not support browser-like functionality.  

# TODO


# Note
Run `golangci-lint run` before commit
