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
	// 解析命令行参数
	var (
		target      = flag.String("target", "", "目标URL或主机")
		templateDir = flag.String("templates", "configs/templates", "漏洞模板目录")
		timeout     = flag.Int("timeout", 30, "超时时间(秒)")
		concurrent  = flag.Int("concurrent", 10, "并发数")
		reportDir   = flag.String("report-dir", "reports", "报告保存目录")
		verbose     = flag.Bool("verbose", false, "显示详细信息")
	)
	flag.Parse()

	// 验证必需参数
	if *target == "" {
		log.Fatal("请指定扫描目标")
	}

	// 初始化日志记录器
	log, err := logger.NewLogger(logger.INFO, "", true)
	if err != nil {
		fmt.Printf("初始化日志记录器失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	// 创建报告目录
	if err := os.MkdirAll(*reportDir, 0755); err != nil {
		log.Error("创建报告目录失败: %v", err)
		os.Exit(1)
	}

	// 创建扫描器
	scanner := vulnscan.NewScanner(*target, time.Duration(*timeout)*time.Second, *concurrent)

	// 加载漏洞模板
	if err := scanner.LoadTemplates(*templateDir); err != nil {
		log.Error("加载漏洞模板失败: %v", err)
		os.Exit(1)
	}

	// 开始扫描
	log.Info("开始对目标 %s 进行漏洞扫描...", *target)
	startTime := time.Now()

	// 执行扫描
	ctx := context.Background()
	results, err := scanner.Scan(ctx)
	if err != nil {
		log.Error("扫描失败: %v", err)
		os.Exit(1)
	}

	// 生成报告
	report := vulnscan.NewReport(*target, results, startTime)

	// 保存JSON报告
	jsonPath := filepath.Join(*reportDir, fmt.Sprintf("vuln_scan_%s.json",
		time.Now().Format("20060102_150405")))
	if err := report.SaveJSON(jsonPath); err != nil {
		log.Error("保存JSON报告失败: %v", err)
	}

	// 保存HTML报告
	htmlPath := filepath.Join(*reportDir, fmt.Sprintf("vuln_scan_%s.html",
		time.Now().Format("20060102_150405")))
	if err := report.SaveHTML(htmlPath); err != nil {
		log.Error("保存HTML报告失败: %v", err)
	}

	// 打印扫描结果摘要
	duration := time.Since(startTime)
	log.Info("\n扫描完成! 用时: %v", duration)
	log.Info("发现漏洞总数: %d", report.TotalVulns)
	log.Info("严重: %d", report.Summary.Critical)
	log.Info("高危: %d", report.Summary.High)
	log.Info("中危: %d", report.Summary.Medium)
	log.Info("低危: %d", report.Summary.Low)
	log.Info("信息: %d", report.Summary.Info)

	// 显示详细信息
	if *verbose {
		log.Info("\n漏洞详情:")
		for _, result := range results {
			log.Info("\n[%s] %s", result.Severity, result.Name)
			log.Info("漏洞ID: %s", result.VulnID)
			log.Info("描述: %s", result.Description)
			log.Info("解决方案: %s", result.Solution)
			if len(result.Details) > 0 {
				log.Info("详细信息:")
				for k, v := range result.Details {
					log.Info("  %s: %v", k, v)
				}
			}
		}
	}

	log.Info("\n报告已保存:")
	log.Info("JSON报告: %s", jsonPath)
	log.Info("HTML报告: %s", htmlPath)
}
