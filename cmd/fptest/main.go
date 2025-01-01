package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/gosecscanner/internal/fingerprint"
)

func main() {
	target := flag.String("target", "", "目标主机或域名")
	ports := flag.String("ports", "80,443,22,21,25,3306", "要扫描的端口列表")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	verbose := flag.Bool("verbose", false, "显示详细信息")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定目标主机或域名")
	}

	// 解析端口列表
	portList := parsePortList(*ports)
	if len(portList) == 0 {
		log.Fatal("请指定有效的端口列表")
	}

	fmt.Printf("\n[+] 开始识别目标 %s 的服务信息...\n", *target)
	scanner := fingerprint.NewScanner(*target, time.Duration(*timeout)*time.Second)

	for _, port := range portList {
		fmt.Printf("\n[*] 正在扫描端口 %d...\n", port)
		info, err := scanner.ScanPort(port)
		if err != nil {
			if *verbose {
				fmt.Printf("端口 %d 扫描失败: %v\n", port, err)
			}
			continue
		}

		// 打印结果
		fmt.Printf("端口 %d:\n", port)
		if info.ServiceName != "" {
			fmt.Printf("  服务: %s\n", info.ServiceName)
		}
		if info.Version != "" {
			fmt.Printf("  版本: %s\n", info.Version)
		}
		if *verbose && info.Banner != "" {
			fmt.Printf("  Banner: %s\n", info.Banner)
		}
		if len(info.Products) > 0 {
			fmt.Printf("  产品: %v\n", info.Products)
		}
		if len(info.Extra) > 0 {
			fmt.Printf("  额外信息:\n")
			for k, v := range info.Extra {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
	}
}

// parsePortList 解析端口列表字符串
func parsePortList(portsStr string) []int {
	var ports []int
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		// 处理端口范围 (例如: "80-100")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))

			if err1 == nil && err2 == nil && start < end {
				for port := start; port <= end; port++ {
					if port > 0 && port < 65536 {
						ports = append(ports, port)
					}
				}
			}
		} else {
			// 处理单个端口
			if port, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				if port > 0 && port < 65536 {
					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}
