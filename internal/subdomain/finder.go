package subdomain

import (
	"context"
)

type Finder struct {
	domain string
}

func NewFinder(domain string) *Finder {
	return &Finder{
		domain: domain,
	}
}

func (f *Finder) Find(ctx context.Context) ([]string, error) {
	var subdomains []string

	// 这里实现实际的子域名发现逻辑
	// 目前返回一个示例结果
	subdomains = append(subdomains, "www."+f.domain)
	subdomains = append(subdomains, "mail."+f.domain)

	return subdomains, nil
}
