package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Marryname/WebScanner/internal/alive"
	"github.com/Marryname/WebScanner/pkg/logger"
)

func main() {
	target := flag.String("target", "", "目标主机或域名")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	threads := flag.Int("threads", 10, "并发线程数")
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

	detector := alive.NewDetector(*target, time.Duration(*timeout)*time.Second, *threads)
	result, err := detector.Detect()
	if err != nil {
		log.Error("存活探测失败: %v", err)
		return
	}

	fmt.Printf("目标: %s\n", *target)
	fmt.Printf("存活状态: %v\n", result.IsAlive)
	if result.IsAlive {
		fmt.Printf("成功的探测方法: %v\n", result.Methods)
		fmt.Printf("响应时间: %v\n", result.ResponseTime)
	}
}
