package fingerprint

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ScanResult 服务识别结果
type ScanResult struct {
	Port        int    `json:"port"`
	ServiceName string `json:"service_name"`
	Version     string `json:"version,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

// Scanner 服务识别扫描器
type Scanner struct {
	target  string
	timeout time.Duration
	db      *Database
}

// NewScanner 创建新的服务识别扫描器
func NewScanner(target string, timeout time.Duration) *Scanner {
	return &Scanner{
		target:  target,
		timeout: timeout,
		db:      NewDatabase(),
	}
}

// Scan 执行服务识别扫描
func (s *Scanner) Scan(ctx context.Context) ([]ScanResult, error) {
	var results []ScanResult

	// 获取目标IP
	ips, err := net.LookupIP(s.target)
	if err != nil {
		return nil, fmt.Errorf("解析目标失败: %v", err)
	}

	// 使用第一个IP地址
	ip := ips[0].String()

	// 扫描常用端口
	commonPorts := []int{80, 443, 22, 21, 25, 3306, 6379, 27017}
	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			if result := s.scanPort(ip, port); result != nil {
				results = append(results, *result)
			}
		}
	}

	return results, nil
}

// scanPort 扫描单个端口
func (s *Scanner) scanPort(ip string, port int) *ScanResult {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	result := &ScanResult{
		Port: port,
	}

	// 尝试获取banner
	banner := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, err := conn.Read(banner)
	if err == nil && n > 0 {
		result.Banner = string(banner[:n])
	}

	// 识别服务
	result.ServiceName = s.db.IdentifyService(port, result.Banner)
	result.Version = s.db.IdentifyVersion(result.Banner)

	return result
}
