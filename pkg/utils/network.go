package utils

import (
	"context"
	"net"
	"time"
)

// DNSResolver 自定义DNS解析器
type DNSResolver struct {
	Timeout time.Duration
	Server  string
}

// NewDNSResolver 创建新的DNS解析器
func NewDNSResolver(server string, timeout time.Duration) *DNSResolver {
	return &DNSResolver{
		Server:  server,
		Timeout: timeout,
	}
}

// LookupIP 查询IP地址
func (r *DNSResolver) LookupIP(domain string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: r.Timeout,
			}
			return d.DialContext(ctx, network, r.Server+":53")
		},
	}

	return resolver.LookupIP(ctx, "ip4", domain)
}
