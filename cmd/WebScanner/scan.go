package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Marryname/WebScanner/internal/alive"
	"github.com/Marryname/WebScanner/internal/cdn"
	"github.com/Marryname/WebScanner/internal/fingerprint"
	"github.com/Marryname/WebScanner/internal/portscan"
	"github.com/Marryname/WebScanner/internal/subdomain"
	"github.com/Marryname/WebScanner/internal/vulnscan"
	"github.com/Marryname/WebScanner/pkg/logger"
	"github.com/spf13/cobra"
)

// 命令行参数
var (
	target     string
	portRange  string
	threads    int
	timeout    int
	modules    []string
	outputFile string
	verbose    bool
)

// 有效的扫描模块
var validModules = map[string]bool{
	"port":      true,
	"subdomain": true,
	"cdn":       true,
	"alive":     true,
	"finger":    true,
	"vuln":      true,
	"all":       true,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "执行安全扫描",
	Long:  `对目标执行综合安全扫描，包括端口扫描、服务识别、漏洞扫描等`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// 验证目标
		if target == "" {
			return fmt.Errorf("请指定扫描目标")
		}

		// 验证并修正参数
		if threads <= 0 {
			threads = 100
		}
		if timeout <= 0 {
			timeout = 5
		}

		// 验证模块
		for _, m := range modules {
			if !validModules[strings.ToLower(m)] {
				return fmt.Errorf("无效的扫描模块: %s", m)
			}
		}

		return nil
	},
	Run: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "扫描目标 (必需)")
	scanCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1000", "端口范围")
	scanCmd.Flags().IntVarP(&threads, "threads", "n", 100, "并发线程数")
	scanCmd.Flags().IntVar(&timeout, "timeout", 5, "超时时间(秒)")
	scanCmd.Flags().StringSliceVarP(&modules, "modules", "m", []string{"all"},
		"扫描模块 (port|subdomain|cdn|alive|finger|vuln|all)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出文件路径")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "显示详细信息")

	scanCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) {
	// 初始化日志记录器
	logLevel := logger.INFO
	if verbose {
		logLevel = logger.DEBUG
	}
	log, err := logger.NewLogger(logLevel, "", true)
	if err != nil {
		fmt.Printf("初始化日志记录器失败: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	startTime := time.Now()
	log.Info("开始扫描目标: %s", target)

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results := make(map[string]interface{})

	// 执行各个模块的扫描
	if err := runScanModules(ctx, results); err != nil {
		log.Error("扫描过程中出错: %v", err)
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

func runScanModules(ctx context.Context, results map[string]interface{}) error {
	// 端口扫描
	if shouldRunModule("port") {
		if err := runPortScan(ctx, results); err != nil {
			log.Error("端口扫描失败: %v", err)
		}
	}

	// 子域名发现
	if shouldRunModule("subdomain") {
		if err := runSubdomainScan(ctx, results); err != nil {
			log.Error("子域名发现失败: %v", err)
		}
	}

	// CDN检测
	if shouldRunModule("cdn") {
		if err := runCDNDetection(results); err != nil {
			log.Error("CDN检测失败: %v", err)
		}
	}

	// 存活探测
	if shouldRunModule("alive") {
		if err := runAliveDetection(results); err != nil {
			log.Error("存活探测失败: %v", err)
		}
	}

	// 服务识别
	if shouldRunModule("finger") && results["ports"] != nil {
		if err := runFingerprint(ctx, results); err != nil {
			log.Error("服务识别失败: %v", err)
		}
	}

	// 漏洞扫描
	if shouldRunModule("vuln") {
		if err := runVulnScan(ctx, results); err != nil {
			log.Error("漏洞扫描失败: %v", err)
		}
	}

	return nil
}

// 各个模块的扫描函数
func runPortScan(ctx context.Context, results map[string]interface{}) error {
	log.Info("执行端口扫描...")
	scanner := portscan.NewPortScanner(target, time.Duration(timeout)*time.Second)
	portResults, err := scanner.Scan(ctx)
	if err != nil {
		return err
	}
	results["ports"] = portResults
	return nil
}

func runSubdomainScan(ctx context.Context, results map[string]interface{}) error {
	log.Info("执行子域名发现...")
	finder := subdomain.NewFinder(target)
	subdomains, err := finder.Find(ctx)
	if err != nil {
		return err
	}
	results["subdomains"] = subdomains
	return nil
}

func runCDNDetection(results map[string]interface{}) error {
	log.Info("执行CDN检测...")
	detector := cdn.NewDetector(target)
	cdnInfo, err := detector.Detect()
	if err != nil {
		return err
	}
	results["cdn"] = cdnInfo
	return nil
}

func runAliveDetection(results map[string]interface{}) error {
	log.Info("执行存活探测...")
	detector := alive.NewDetector(target, time.Duration(timeout)*time.Second, threads)
	aliveResult, err := detector.Detect()
	if err != nil {
		return err
	}
	results["alive"] = aliveResult
	return nil
}

func runFingerprint(ctx context.Context, results map[string]interface{}) error {
	log.Info("执行服务识别...")
	scanner := fingerprint.NewScanner(target, time.Duration(timeout)*time.Second)
	fingerResults, err := scanner.Scan(ctx)
	if err != nil {
		return err
	}
	results["services"] = fingerResults
	return nil
}

func runVulnScan(ctx context.Context, results map[string]interface{}) error {
	log.Info("执行漏洞扫描...")
	scanner := vulnscan.NewScanner(target, time.Duration(timeout)*time.Second, threads)
	vulnResults, err := scanner.Scan(ctx)
	if err != nil {
		return err
	}
	results["vulnerabilities"] = vulnResults
	return nil
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

	// 创建输出目录
	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 保存为JSON格式
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

func printSummary(results map[string]interface{}) {
	log.Info("\n扫描结果摘要:")

	if ports, ok := results["ports"].([]portscan.ScanResult); ok {
		log.Info("开放端口: %d 个", len(ports))
		for _, port := range ports {
			log.Info("  - %d (%s)", port.Port, port.Service)
		}
	}

	if subdomains, ok := results["subdomains"].([]string); ok {
		log.Info("发现子域名: %d 个", len(subdomains))
		for _, subdomain := range subdomains {
			log.Info("  - %s", subdomain)
		}
	}

	if cdnInfo, ok := results["cdn"].(*cdn.CDNInfo); ok {
		log.Info("CDN服务: %v", cdnInfo.IsCDN)
	}

	if vulns, ok := results["vulnerabilities"].([]vulnscan.VulnResult); ok {
		log.Info("发现漏洞: %d 个", len(vulns))
		for _, vuln := range vulns {
			log.Info("  - [%s] %s", vuln.Severity, vuln.Name)
		}
	}
}
