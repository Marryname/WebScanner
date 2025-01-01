package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortScanner 端口扫描器结构体
type PortScanner struct {
	target  string        // 扫描目标
	timeout time.Duration // 超时时间
	mutex   sync.Mutex    // 互斥锁,用于保护results
	results []ScanResult  // 扫描结果
}

type ScanResult struct {
	Port    int
	State   string
	Service string
}

func NewPortScanner(target string, timeout time.Duration) *PortScanner {
	return &PortScanner{
		target:  target,
		timeout: timeout,
	}
}

func (s *PortScanner) ScanPort(port int) ScanResult {
	target := fmt.Sprintf("%s:%d", s.target, port)
	conn, err := net.DialTimeout("tcp", target, s.timeout)

	if err != nil {
		return ScanResult{Port: port, State: "closed"}
	}

	defer conn.Close()
	return ScanResult{Port: port, State: "open"}
}

func (s *PortScanner) ParallelScan(start, end, threads int) []ScanResult {
	ports := make(chan int, threads)
	results := make(chan ScanResult)
	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			for port := range ports {
				results <- s.ScanPort(port)
			}
			wg.Done()
		}()
	}

	// 发送端口到通道
	go func() {
		for port := start; port <= end; port++ {
			ports <- port
		}
		close(ports)
	}()

	// 收集结果
	go func() {
		wg.Wait()
		close(results)
	}()

	var scanResults []ScanResult
	for result := range results {
		if result.State == "open" {
			scanResults = append(scanResults, result)
		}
	}

	return scanResults
}
