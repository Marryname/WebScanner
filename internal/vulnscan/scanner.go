package vulnscan

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// VulnResult 漏洞扫描结果
type VulnResult struct {
	Target      string
	VulnID      string
	Name        string
	Severity    string
	Description string
	Solution    string
	Details     map[string]interface{}
	Timestamp   time.Time
}

// Scanner 漏洞扫描器
type Scanner struct {
	target     string
	timeout    time.Duration
	concurrent int
	templates  *TemplateManager
	client     *http.Client
}

// NewScanner 创建新的漏洞扫描器
func NewScanner(target string, timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		target:     target,
		timeout:    timeout,
		concurrent: concurrent,
		templates:  NewTemplateManager(),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Scan 执行漏洞扫描
func (s *Scanner) Scan(ctx context.Context) ([]*VulnResult, error) {
	var results []*VulnResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, s.concurrent)

	// 获取所有漏洞模板
	templates := s.templates.GetTemplates()
	semaphore := make(chan struct{}, s.concurrent)

	for _, tmpl := range templates {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case semaphore <- struct{}{}:
		}

		wg.Add(1)
		go func(t *Template) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			result, err := s.scanWithTemplate(ctx, t)
			if err != nil {
				errChan <- err
				return
			}

			if result != nil {
				mutex.Lock()
				results = append(results, result)
				mutex.Unlock()
			}
		}(tmpl)
	}

	wg.Wait()
	close(errChan)

	// 收集错误
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("扫描过程中发生错误: %v", errs)
	}

	return results, nil
}

// scanWithTemplate 使用指定模板进行扫描
func (s *Scanner) scanWithTemplate(ctx context.Context, tmpl *Template) (*VulnResult, error) {
	// 检查目标是否适用于此模板
	if !tmpl.IsApplicable(s.target) {
		return nil, nil
	}

	// 执行漏洞检测
	matched, details, err := tmpl.Execute(ctx, s.client, s.target)
	if err != nil {
		return nil, fmt.Errorf("模板执行失败 %s: %v", tmpl.ID, err)
	}

	if !matched {
		return nil, nil
	}

	// 创建漏洞结果
	return &VulnResult{
		Target:      s.target,
		VulnID:      tmpl.ID,
		Name:        tmpl.Name,
		Severity:    tmpl.Severity,
		Description: tmpl.Description,
		Solution:    tmpl.Solution,
		Details:     details,
		Timestamp:   time.Now(),
	}, nil
}
