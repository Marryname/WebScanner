package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Marryname/WebScanner/internal/vulnscan"
	"github.com/Marryname/WebScanner/pkg/logger"
)

func main() {
	target := flag.String("target", "", "目标URL或主机")
	templateDir := flag.String("templates", "configs/templates", "漏洞模板目录")
	timeout := flag.Int("timeout", 30, "超时时间(秒)")
	concurrent := flag.Int("concurrent", 10, "并发数")
	reportDir := flag.String("report-dir", "reports", "报告保存目录")
	verbose := flag.Bool("verbose", false, "显示详细信息")
	flag.Parse()

	if *target == "" {
		log.Fatal("请指定扫描目标")
	}

	log, err := logger.NewLogger(logger.INFO, "", true)
	if err != nil {
		fmt.Printf("初始化日志记录器失败: %v\n", err)
		return
	}
	defer log.Close()

	// 创建报告目录
	if err := os.MkdirAll(*reportDir, 0755); err != nil {
		log.Error("创建报告目录失败: %v", err)
		return
	}

	fmt.Printf("\n[+] 开始对目标 %s 进行漏洞扫描...\n", *target)

	// 创建扫描器
	scanner := vulnscan.NewScanner(*target, time.Duration(*timeout)*time.Second, *concurrent)

	// 加载漏洞模板
	if err := scanner.LoadTemplates(*templateDir); err != nil {
		log.Error("加载漏洞模板失败: %v", err)
		return
	}

	startTime := time.Now()
	ctx := context.Background()

	// 执行扫描
	results, err := scanner.Scan(ctx)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 生成报告
	report := vulnscan.NewReport(*target, results, startTime)

	// 保存JSON报告
	jsonPath := filepath.Join(*reportDir, fmt.Sprintf("vuln_scan_%s.json",
		time.Now().Format("20060102_150405")))
	if err := report.SaveJSON(jsonPath); err != nil {
		log.Printf("保存JSON报告失败: %v", err)
	}

	// 保存HTML报告
	htmlPath := filepath.Join(*reportDir, fmt.Sprintf("vuln_scan_%s.html",
		time.Now().Format("20060102_150405")))
	if err := report.SaveHTML(htmlPath); err != nil {
		log.Printf("保存HTML报告失败: %v", err)
	}

	// 打印扫描结果摘要
	fmt.Printf("\n扫描完成! 用时: %v\n", time.Since(startTime))
	fmt.Printf("发现漏洞总数: %d\n", report.TotalVulns)
	fmt.Printf("严重: %d\n", report.Summary.Critical)
	fmt.Printf("高危: %d\n", report.Summary.High)
	fmt.Printf("中危: %d\n", report.Summary.Medium)
	fmt.Printf("低危: %d\n", report.Summary.Low)
	fmt.Printf("信息: %d\n", report.Summary.Info)

	// 显示详细信息
	if *verbose {
		fmt.Printf("\n漏洞详情:\n")
		for _, result := range results {
			fmt.Printf("\n[%s] %s\n", result.Severity, result.Name)
			fmt.Printf("漏洞ID: %s\n", result.VulnID)
			fmt.Printf("描述: %s\n", result.Description)
			fmt.Printf("解决方案: %s\n", result.Solution)
			if len(result.Details) > 0 {
				fmt.Printf("详细信息:\n")
				for k, v := range result.Details {
					fmt.Printf("  %s: %v\n", k, v)
				}
			}
		}
	}

	fmt.Printf("\n报告已保存:\n")
	fmt.Printf("JSON报告: %s\n", jsonPath)
	fmt.Printf("HTML报告: %s\n", htmlPath)
}
