package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/yourusername/gosecscanner/internal/alive"
)

func main() {
	target := flag.String("target", "", "目标主机或域名")
	timeout := flag.Int("timeout", 5, "超时时间(秒)")
	concurrent := flag.Int("concurrent", 10, "并发数")
	methods := flag.String("methods", "all", "探测方法(icmp,tcp,http,all)")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定目标主机或域名")
	}

	fmt.Printf("\n[+] 开始探测目标 %s 的存活状态...\n", *target)

	detector := alive.NewDetector(*target, time.Duration(*timeout)*time.Second, *concurrent)

	// 如果指定了特定方法，只测试指定方法
	if *methods != "all" {
		testSpecificMethods(*target, detector, strings.Split(*methods, ","))
		return
	}

	// 执行完整探测
	result, err := detector.Detect()
	if err != nil {
		log.Printf("探测失败: %v", err)
		return
	}

	// 打印结果
	fmt.Printf("\n探测结果:\n")
	fmt.Printf("目标: %s\n", result.Target)
	fmt.Printf("存活状态: %v\n", result.IsAlive)
	if result.IsAlive {
		fmt.Printf("成功的探测方法: %v\n", result.Methods)
		fmt.Printf("响应延迟: %dms\n", result.Latency)
	}
	if result.Error != nil {
		fmt.Printf("错误信息: %v\n", result.Error)
	}
}

func testSpecificMethods(target string, detector *alive.Detector, methods []string) {
	for _, method := range methods {
		var alive bool
		var err error

		fmt.Printf("\n[*] 正在使用 %s 方法进行探测...\n", method)

		switch strings.ToLower(method) {
		case "icmp":
			alive, err = detector.icmpDetect()
		case "tcp":
			alive, err = detector.tcpDetect()
		case "http":
			alive, err = detector.httpDetect()
		default:
			fmt.Printf("不支持的探测方法: %s\n", method)
			continue
		}

		if err != nil {
			fmt.Printf("%s 探测失败: %v\n", method, err)
		} else {
			fmt.Printf("%s 探测结果: %v\n", method, alive)
		}
	}
}
