package cdn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// CDNInfo 存储 CDN 检测结果
type CDNInfo struct {
	Domain      string
	IsCDN       bool
	CNAMEs      []string
	IPs         []string
	TTL         int
	GeoLocation map[string][]string // IP所属地理位置
}

// Detector CDN检测器结构体
type Detector struct {
	target           string
	cdnCNAMEKeywords []string
	timeout          time.Duration
}

// NewDetector 创建新的CDN检测器
func NewDetector(target string) *Detector {
	return &Detector{
		target: target,
		cdnCNAMEKeywords: []string{
			"cdn", "cloudfront", "akamai", "fastly",
			"cloudflare", "edgecast", "chinacache",
			"wscdns", "cdn.dnsv1",
		},
	}
}

// Detect 执行CDN检测
func (d *Detector) Detect() (*CDNInfo, error) {
	info := &CDNInfo{
		Domain:      d.target,
		GeoLocation: make(map[string][]string),
	}

	// 1. 检查CNAME记录
	cnames, err := d.checkCNAME()
	if err != nil {
		return nil, fmt.Errorf("CNAME检查失败: %v", err)
	}
	info.CNAMEs = cnames

	// 2. 获取IP地址和TTL
	ips, ttl, err := d.getIPsAndTTL()
	if err != nil {
		return nil, fmt.Errorf("IP获取失败: %v", err)
	}
	info.IPs = ips
	info.TTL = ttl

	// 3. 检查是否为CDN
	info.IsCDN = d.analyzeResults(info)

	return info, nil
}

// checkCNAME 检查CNAME记录
func (d *Detector) checkCNAME() ([]string, error) {
	cnames, err := net.LookupCNAME(d.target)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, cname := range strings.Split(cnames, "\n") {
		if cname != "" {
			results = append(results, strings.TrimSuffix(cname, "."))
		}
	}
	return results, nil
}

// getIPsAndTTL 获取IP地址和TTL值
func (d *Detector) getIPsAndTTL() ([]string, int, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	ips, err := resolver.LookupIP(context.Background(), "ip4", d.target)
	if err != nil {
		return nil, 0, err
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	// 获取TTL值（这里使用模拟值，实际需要通过DNS查询获取）
	ttl := 300 // 默认TTL值

	return ipStrings, ttl, nil
}

// analyzeResults 分析结果判断是否为CDN
func (d *Detector) analyzeResults(info *CDNInfo) bool {
	// 1. 检查CNAME是否包含CDN关键字
	for _, cname := range info.CNAMEs {
		for _, keyword := range d.cdnCNAMEKeywords {
			if strings.Contains(strings.ToLower(cname), keyword) {
				return true
			}
		}
	}

	// 2. 检查是否有多个不同地理位置的IP
	if len(info.IPs) > 3 {
		return true
	}

	// 3. 检查TTL值是否较小（CDN通常使用较小的TTL值）
	if info.TTL < 300 {
		return true
	}

	return false
}

// GetIPGeoLocation 获取IP地理位置信息
func (d *Detector) GetIPGeoLocation(ip string) (string, error) {
	// 这里可以接入第三方IP地理位置查询服务
	// 例如：ipapi.co, ip-api.com等
	// 示例实现：
	return "Unknown", nil
}

// SetTimeout 设置超时时间
func (d *Detector) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
}

// matchCDNPattern 检查CNAME是否匹配CDN模式
func (d *Detector) matchCDNPattern(cname string) bool {
	for _, keyword := range d.cdnCNAMEKeywords {
		if strings.Contains(strings.ToLower(cname), keyword) {
			return true
		}
	}
	return false
}

// SetCustomKeywords 设置自定义CDN关键字
func (d *Detector) SetCustomKeywords(keywords []string) {
	d.cdnCNAMEKeywords = keywords
}
