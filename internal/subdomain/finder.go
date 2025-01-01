package subdomain

import (
	"net"
	"time"
)

type SubdomainFinder struct {
	domain     string
	wordlist   []string
	results    []string
	timeout    time.Duration
	concurrent int
}

func NewSubdomainFinder(domain string) *SubdomainFinder {
	return &SubdomainFinder{
		domain: domain,
	}
}

func (f *SubdomainFinder) DNSBruteforce() []string {
	var results []string

	for _, word := range f.wordlist {
		subdomain := word + "." + f.domain
		ips, err := net.LookupHost(subdomain)
		if err == nil && len(ips) > 0 {
			results = append(results, subdomain)
		}
	}

	return results
}

// AddCommonPrefixes 添加常用子域名前缀
func (f *SubdomainFinder) AddCommonPrefixes() {
	commonPrefixes := []string{
		"www", "mail", "email", "ftp", "smtp", "pop", "pop3", "imap",
		"api", "dev", "developer", "test", "testing", "staging",
		"admin", "administrator", "blog", "forum", "bbs",
		"ns1", "ns2", "dns1", "dns2", "mx1", "mx2",
		"vpn", "ssh", "remote", "git", "svn",
		"db", "database", "sql", "mysql", "oracle",
		"shop", "store", "payment", "ssl", "secure",
		"mobile", "m", "app", "api", "ws", "ww",
		"support", "help", "client", "cp", "portal",
		"cloud", "cdn", "static", "img", "images", "assets",
		"auth", "login", "webmail", "beta", "demo",
	}
	f.wordlist = append(f.wordlist, commonPrefixes...)
}

// SetTimeout 设置超时时间
func (f *SubdomainFinder) SetTimeout(timeout time.Duration) {
	f.timeout = timeout
}

// SetConcurrent 设置并发数
func (f *SubdomainFinder) SetConcurrent(concurrent int) {
	f.concurrent = concurrent
}
