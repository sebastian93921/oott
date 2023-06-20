# OOTT - OSINT Offensive Toolkit
Note: This application only works on UNIX / LINUX like operating system

# Example
## Sub-domain scanning
```
./oott -d example.com -subdomain-scan -fast-scan -http-status-scan -wordlist /mnt/f/workspace/oott/wordlist.txt
```

## Email scanning
```
./oott -d example.com -email-scan
```

## Secret scanning
```
./oott -d example.com -secret-scan -key-words test1,test2,test3,test4
```

# TODO
- [ ] Port [Wappalyzer](https://github.com/wappalyzer/wappalyzer)

# Note
Run `golangci-lint run` before commit
