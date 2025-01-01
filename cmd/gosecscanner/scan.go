package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Marryname/WebScanner/internal/alive"
	"github.com/Marryname/WebScanner/internal/cdn"
	"github.com/Marryname/WebScanner/internal/fingerprint"
	"github.com/Marryname/WebScanner/internal/portscan"
	"github.com/Marryname/WebScanner/internal/subdomain"
	"github.com/Marryname/WebScanner/internal/vulnscan"
	"github.com/spf13/cobra"
)

var (
	target     string
	portRange  string
	threads    int
	timeout    int
	modules    []string
	outputFile string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "执行安全扫描",
	Long:  `对目标执行综合安全扫描，包括端口扫描、服务识别、漏洞扫描等`,
	Run:   runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标 (必需)")
	scanCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1000", "端口范围")
	scanCmd.Flags().IntVarP(&threads, "threads", "n", 100, "并发线程数")
	scanCmd.Flags().IntVar(&timeout, "timeout", 5, "超时时间(秒)")
	scanCmd.Flags().StringSliceVarP(&modules, "modules", "m", []string{"all"},
		"扫描模块 (port|subdomain|cdn|alive|finger|vuln|all)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件路径")

	scanCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) {
	startTime := time.Now()
	log.Info("开始扫描目标: %s", target)

	ctx := context.Background()
	results := make(map[string]interface{})

	// 端口扫描
	if shouldRunModule("port") {
		log.Info("执行端口扫描...")
		portScanner := portscan.NewPortScanner(target, time.Duration(timeout)*time.Second)
		if portResults, err := portScanner.Scan(ctx); err == nil {
			results["ports"] = portResults
		}
	}

	// 子域名发现
	if shouldRunModule("subdomain") {
		log.Info("执行子域名发现...")
		subdomainFinder := subdomain.NewFinder(target)
		if subdomains, err := subdomainFinder.Find(ctx); err == nil {
			results["subdomains"] = subdomains
		}
	}

	// CDN检测
	if shouldRunModule("cdn") {
		log.Info("执行CDN检测...")
		cdnDetector := cdn.NewDetector(target)
		if cdnInfo, err := cdnDetector.Detect(); err == nil {
			results["cdn"] = cdnInfo
		}
	}

	// 存活探测
	if shouldRunModule("alive") {
		log.Info("执行存活探测...")
		aliveDetector := alive.NewDetector(target, time.Duration(timeout)*time.Second, threads)
		if aliveResult, err := aliveDetector.Detect(); err == nil {
			results["alive"] = aliveResult
		}
	}

	// 服务识别
	if shouldRunModule("finger") && results["ports"] != nil {
		log.Info("执行服务识别...")
		fingerprinter := fingerprint.NewScanner(target, time.Duration(timeout)*time.Second)
		if fingerResults, err := fingerprinter.Scan(ctx); err == nil {
			results["services"] = fingerResults
		}
	}

	// 漏洞扫描
	if shouldRunModule("vuln") {
		log.Info("执行漏洞扫描...")
		vulnScanner := vulnscan.NewScanner(target, time.Duration(timeout)*time.Second, threads)
		if vulnResults, err := vulnScanner.Scan(ctx); err == nil {
			results["vulnerabilities"] = vulnResults
		}
	}

	// 生成报告
	duration := time.Since(startTime)
	log.Info("扫描完成，用时: %v", duration)

	if err := saveResults(results, outputFile); err != nil {
		log.Error("保存结果失败: %v", err)
	}

	// 打印摘要
	printSummary(results)
}

func shouldRunModule(module string) bool {
	if len(modules) == 0 {
		return false
	}
	for _, m := range modules {
		if m == "all" || m == module {
			return true
		}
	}
	return false
}

func saveResults(results map[string]interface{}, outputFile string) error {
	if outputFile == "" {
		return nil
	}

	// 实现结果保存逻辑...
	return nil
}

func printSummary(results map[string]interface{}) {
	fmt.Println("\n扫描结果摘要:")

	if ports, ok := results["ports"].([]portscan.ScanResult); ok {
		fmt.Printf("开放端口: %d 个\n", len(ports))
	}

	if subdomains, ok := results["subdomains"].([]string); ok {
		fmt.Printf("发现子域名: %d 个\n", len(subdomains))
	}

	if cdnInfo, ok := results["cdn"].(*cdn.CDNInfo); ok {
		fmt.Printf("CDN服务: %v\n", cdnInfo.IsCDN)
	}

	if vulns, ok := results["vulnerabilities"].([]vulnscan.VulnResult); ok {
		fmt.Printf("发现漏洞: %d 个\n", len(vulns))
	}
}
