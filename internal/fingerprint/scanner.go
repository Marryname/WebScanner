package fingerprint

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
)

// ServiceInfo 存储服务识别结果
type ServiceInfo struct {
	Port        int
	Protocol    string
	ServiceName string
	Version     string
	Banner      string
	Products    []string
	Extra       map[string]string
}

// Scanner 服务识别扫描器
type Scanner struct {
	target     string
	timeout    time.Duration
	probeData  map[string][]byte
	signatures map[string][]*regexp.Regexp
}

// NewScanner 创建新的服务识别扫描器
func NewScanner(target string, timeout time.Duration) *Scanner {
	s := &Scanner{
		target:     target,
		timeout:    timeout,
		probeData:  make(map[string][]byte),
		signatures: make(map[string][]*regexp.Regexp),
	}
	s.loadSignatures()
	return s
}

// ScanPort 扫描指定端口的服务
func (s *Scanner) ScanPort(port int) (*ServiceInfo, error) {
	info := &ServiceInfo{
		Port:     port,
		Protocol: "tcp",
		Extra:    make(map[string]string),
	}

	// 1. 获取Banner
	banner, err := s.grabBanner(port)
	if err != nil {
		return nil, fmt.Errorf("banner获取失败: %v", err)
	}
	info.Banner = banner

	// 2. 匹配服务指纹
	if err := s.matchSignatures(info); err != nil {
		return nil, fmt.Errorf("指纹匹配失败: %v", err)
	}

	// 3. 进行版本识别
	s.detectVersion(info)

	return info, nil
}

// grabBanner 获取服务Banner
func (s *Scanner) grabBanner(port int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// 建立TCP连接
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", s.target, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	// 发送探测数据
	probes := [][]byte{
		[]byte("\r\n"),
		[]byte("HEAD / HTTP/1.0\r\n\r\n"),
		[]byte("GET / HTTP/1.0\r\n\r\n"),
	}

	var banner string
	for _, probe := range probes {
		// 发送探测数据
		_, err = conn.Write(probe)
		if err != nil {
			continue
		}

		// 读取响应
		reader := bufio.NewReader(conn)
		buffer := make([]byte, 2048)
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			continue
		}

		if n > 0 {
			banner = string(bytes.TrimSpace(buffer[:n]))
			break
		}
	}

	return banner, nil
}

// matchSignatures 匹配服务指纹
func (s *Scanner) matchSignatures(info *ServiceInfo) error {
	if info.Banner == "" {
		return nil
	}

	for service, patterns := range s.signatures {
		for _, pattern := range patterns {
			if pattern.MatchString(info.Banner) {
				info.ServiceName = service
				// 提取其他有用信息
				matches := pattern.FindStringSubmatch(info.Banner)
				if len(matches) > 1 {
					info.Extra["signature_match"] = matches[1]
				}
				return nil
			}
		}
	}

	return nil
}

// detectVersion 检测服务版本
func (s *Scanner) detectVersion(info *ServiceInfo) {
	// 常见版本号模式
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)version[:/\s]+([0-9.]+)`),
		regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)/([0-9]+\.[0-9]+)`),
	}

	for _, pattern := range versionPatterns {
		matches := pattern.FindStringSubmatch(info.Banner)
		if len(matches) > 1 {
			info.Version = matches[1]
			break
		}
	}
}

// loadSignatures 加载服务指纹库
func (s *Scanner) loadSignatures() {
	// 这里应该从配置文件加载，这里只是示例
	signatures := map[string][]string{
		"SSH": {
			`^SSH-([0-9]+\.[0-9]+)`,
			`^OpenSSH`,
		},
		"HTTP": {
			`^HTTP/[0-9]`,
			`^Server: Apache`,
			`^Server: nginx`,
		},
		"FTP": {
			`^220.*FTP`,
			`^220-FileZilla`,
		},
		"SMTP": {
			`^220.*SMTP`,
			`^220.*Postfix`,
		},
		"MySQL": {
			`^.\x00\x00\x00\x0a[0-9]+\.[0-9]+\.[0-9]+`,
		},
	}

	// 编译正则表达式
	for service, patterns := range signatures {
		var regexps []*regexp.Regexp
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err == nil {
				regexps = append(regexps, re)
			}
		}
		s.signatures[service] = regexps
	}
}
