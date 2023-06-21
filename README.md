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


# TODO
- [x] Port [Wappalyzer](https://github.com/wappalyzer/wappalyzer)

# Note
Run `golangci-lint run` before commit
