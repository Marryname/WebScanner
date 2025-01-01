package alive

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DetectResult 存储探测结果
type DetectResult struct {
	Target  string
	IsAlive bool
	Methods []string // 成功的探测方法
	Latency int64    // 响应延迟（毫秒）
	Error   error
}

// Detector 存活探测器
type Detector struct {
	target     string
	timeout    time.Duration
	concurrent int
}

// NewDetector 创建新的存活探测器
func NewDetector(target string, timeout time.Duration, concurrent int) *Detector {
	return &Detector{
		target:     target,
		timeout:    timeout,
		concurrent: concurrent,
	}
}

// Detect 执行综合探测
func (d *Detector) Detect() (*DetectResult, error) {
	result := &DetectResult{
		Target: d.target,
	}

	// 并发执行多种探测方法
	var wg sync.WaitGroup
	resultChan := make(chan string, 3) // 存储成功的探测方法
	errorChan := make(chan error, 3)   // 存储错误信息

	// 1. ICMP探测
	wg.Add(1)
	go func() {
		defer wg.Done()
		if alive, err := d.icmpDetect(); err != nil {
			errorChan <- fmt.Errorf("ICMP探测失败: %v", err)
		} else if alive {
			resultChan <- "ICMP"
		}
	}()

	// 2. TCP SYN探测
	wg.Add(1)
	go func() {
		defer wg.Done()
		if alive, err := d.tcpDetect(); err != nil {
			errorChan <- fmt.Errorf("TCP探测失败: %v", err)
		} else if alive {
			resultChan <- "TCP"
		}
	}()

	// 3. HTTP探测
	wg.Add(1)
	go func() {
		defer wg.Done()
		if alive, err := d.httpDetect(); err != nil {
			errorChan <- fmt.Errorf("HTTP探测失败: %v", err)
		} else if alive {
			resultChan <- "HTTP"
		}
	}()

	// 等待所有探测完成
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// 收集结果
	for method := range resultChan {
		result.Methods = append(result.Methods, method)
	}

	// 收集错误
	var errors []string
	for err := range errorChan {
		errors = append(errors, err.Error())
	}

	if len(result.Methods) > 0 {
		result.IsAlive = true
	} else if len(errors) > 0 {
		result.Error = fmt.Errorf("探测失败: %s", strings.Join(errors, "; "))
	}

	return result, nil
}

// icmpDetect 执行ICMP探测
func (d *Detector) icmpDetect() (bool, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", d.timeout/time.Millisecond), d.target)
	default: // Linux, Darwin
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", d.timeout/time.Second), d.target)
	}

	if err := cmd.Run(); err != nil {
		return false, nil // 目标不可达
	}
	return true, nil
}

// tcpDetect 执行TCP SYN探测
func (d *Detector) tcpDetect() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	// 常用端口列表
	ports := []int{80, 443, 22, 21, 25, 3389}

	for _, port := range ports {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", d.target, port))
		if err == nil {
			conn.Close()
			return true, nil
		}
	}

	return false, nil
}

// httpDetect 执行HTTP请求探测
func (d *Detector) httpDetect() (bool, error) {
	client := &http.Client{
		Timeout: d.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向
		},
	}

	// 尝试HTTP和HTTPS
	protocols := []string{"http", "https"}

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, d.target)
		req, err := http.NewRequest("HEAD", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return true, nil
		}
	}

	return false, nil
}
