package common

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParsePortRange 解析端口范围
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int
	parts := strings.Split(portRange, ",")

	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, err
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, err
			}

			for port := start; port <= end; port++ {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
		} else {
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			if port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}

	return ports, nil
}

// IsValidDomain 检查域名是否有效
func IsValidDomain(domain string) bool {
	if len(domain) > 255 {
		return false
	}

	if !strings.Contains(domain, ".") {
		return false
	}

	for _, part := range strings.Split(domain, ".") {
		if len(part) > 63 || len(part) == 0 {
			return false
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$`).MatchString(part) {
			return false
		}
	}

	return true
}

// IsValidIP 检查IP地址是否有效
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// RetryWithTimeout 带超时的重试函数
func RetryWithTimeout(attempts int, timeout time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		done := make(chan error)
		go func() {
			done <- fn()
		}()

		select {
		case err = <-done:
			if err == nil {
				return nil
			}
		case <-time.After(timeout):
			err = fmt.Errorf("operation timed out")
		}
	}
	return err
}
