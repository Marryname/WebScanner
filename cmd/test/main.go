package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/gosecscanner/internal/portscan"
	"github.com/yourusername/gosecscanner/internal/subdomain"
)

func main() {
	target := flag.String("target", "", "目标主机或域名")
	mode := flag.String("mode", "all", "扫描模式: port/subdomain/all")
	startPort := flag.Int("start-port", 1, "起始端口")
	endPort := flag.Int("end-port", 1000, "结束端口")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定目标主机或域名")
	}

	// 端口扫描测试
	if *mode == "port" || *mode == "all" {
		fmt.Println("\n[+] 开始端口扫描...")
		scanner := portscan.NewPortScanner(*target, time.Duration(*timeout)*time.Second)
		results := scanner.ParallelScan(*startPort, *endPort, 100)

		fmt.Printf("\n发现开放端口:\n")
		for _, result := range results {
			fmt.Printf("- 端口 %d (%s)\n", result.Port, result.Service)
		}
	}

	// 子域名发现测试
	if *mode == "subdomain" || *mode == "all" {
		fmt.Println("\n[+] 开始子域名发现...")
		finder := subdomain.NewSubdomainFinder(*target)
		// 添加常用子域名前缀
		finder.AddCommonPrefixes()

		results := finder.DNSBruteforce()
		fmt.Printf("\n发现子域名:\n")
		for _, subdomain := range results {
			fmt.Printf("- %s\n", subdomain)
		}
	}
}
