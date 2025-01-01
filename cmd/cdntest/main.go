package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/gosecscanner/internal/cdn"
)

func main() {
	target := flag.String("target", "", "目标域名")
	timeout := flag.Int("timeout", 10, "超时时间(秒)")
	verbose := flag.Bool("verbose", false, "显示详细信息")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定目标域名")
	}

	fmt.Printf("\n[+] 开始检测目标 %s 的CDN信息...\n", *target)

	detector := cdn.NewDetector(*target)
	detector.SetTimeout(time.Duration(*timeout) * time.Second)

	info, err := detector.Detect()
	if err != nil {
		log.Fatalf("CDN检测失败: %v", err)
	}

	// 打印检测结果
	fmt.Printf("\n检测结果:\n")
	fmt.Printf("是否使用CDN: %v\n", info.IsCDN)

	if *verbose {
		if len(info.CNAMEs) > 0 {
			fmt.Printf("\nCNAME记录:\n")
			for _, cname := range info.CNAMEs {
				fmt.Printf("- %s\n", cname)
			}
		}

		if len(info.IPs) > 0 {
			fmt.Printf("\nIP地址:\n")
			for _, ip := range info.IPs {
				fmt.Printf("- %s\n", ip)
			}
		}

		fmt.Printf("\nTTL值: %d\n", info.TTL)

		if len(info.GeoLocation) > 0 {
			fmt.Printf("\n地理位置信息:\n")
			for ip, loc := range info.GeoLocation {
				fmt.Printf("- %s: %v\n", ip, loc)
			}
		}
	}
}
