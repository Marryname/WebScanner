package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Marryname/WebScanner/internal/fingerprint"
	"github.com/Marryname/WebScanner/pkg/logger"
)

func main() {
	target := flag.String("target", "", "目标主机或域名")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定测试目标")
	}

	log, err := logger.NewLogger(logger.INFO, "", true)
	if err != nil {
		fmt.Printf("初始化日志记录器失败: %v\n", err)
		return
	}
	defer log.Close()

	scanner := fingerprint.NewScanner(*target, time.Duration(*timeout)*time.Second)
	results, err := scanner.Scan(context.Background())
	if err != nil {
		log.Error("服务识别失败: %v", err)
		return
	}

	for _, result := range results {
		fmt.Printf("端口 %d:\n", result.Port)
		fmt.Printf("  服务: %s\n", result.ServiceName)
		fmt.Printf("  版本: %s\n", result.Version)
		if result.Banner != "" {
			fmt.Printf("  Banner: %s\n", result.Banner)
		}
	}
}
