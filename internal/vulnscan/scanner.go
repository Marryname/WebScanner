package vulnscan

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// VulnResult 漏洞扫描结果
type VulnResult struct {
	VulnID      string                 `json:"vuln_id"`
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Solution    string                 `json:"solution"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
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
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if concurrent <= 0 {
		concurrent = 10
	}

	return &Scanner{
		target:     target,
		timeout:    timeout,
		concurrent: concurrent,
		templates:  NewTemplateManager(),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// LoadTemplates 加载漏洞模板
func (s *Scanner) LoadTemplates(dir string) error {
	if dir == "" {
		return fmt.Errorf("template directory cannot be empty")
	}
	return s.templates.LoadTemplates(dir)
}

// Scan 执行漏洞扫描
func (s *Scanner) Scan(ctx context.Context) ([]VulnResult, error) {
	if _, err := url.Parse(s.target); err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	var (
		results []VulnResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		errChan = make(chan error, 1)
	)

	// 创建工作通道
	templateChan := make(chan *Template, s.concurrent)

	// 启动工作协程
	for i := 0; i < s.concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for template := range templateChan {
				select {
				case <-ctx.Done():
					return
				default:
					if result := s.scanWithTemplate(ctx, template); result != nil {
						mu.Lock()
						results = append(results, *result)
						mu.Unlock()
					}
				}
			}
		}()
	}

	// 发送模板到工作通道
	go func() {
		for _, template := range s.templates.templates {
			select {
			case <-ctx.Done():
				close(templateChan)
				return
			case templateChan <- template:
			}
		}
		close(templateChan)
	}()

	// 等待所有工作完成
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// 等待完成或上下文取消
	select {
	case <-ctx.Done():
		return results, ctx.Err()
	case err := <-errChan:
		return results, err
	}
}

// scanWithTemplate 使用单个模板进行扫描
func (s *Scanner) scanWithTemplate(ctx context.Context, template *Template) *VulnResult {
	// 检查模板是否适用于目标
	if !s.isTemplateApplicable(template) {
		return nil
	}

	// 创建结果对象
	result := &VulnResult{
		VulnID:      template.ID,
		Name:        template.Name,
		Severity:    template.Severity,
		Description: template.Description,
		Solution:    template.Solution,
		Details:     make(map[string]interface{}),
		Timestamp:   time.Now(),
	}

	// 执行漏洞检测
	matched, details, err := s.executeTemplate(ctx, template)
	if err != nil {
		result.Details["error"] = err.Error()
		return result
	}

	if matched {
		result.Details = details
		return result
	}

	return nil
}

// isTemplateApplicable 检查模板是否适用于目标
func (s *Scanner) isTemplateApplicable(template *Template) bool {
	if template == nil {
		return false
	}

	// 检查必需字段
	if template.ID == "" || template.Name == "" {
		return false
	}

	// 检查匹配器
	if len(template.Matchers) == 0 {
		return false
	}

	return true
}

// executeTemplate 执行模板检测
func (s *Scanner) executeTemplate(ctx context.Context, template *Template) (bool, map[string]interface{}, error) {
	details := map[string]interface{}{
		"check_time": time.Now().Format(time.RFC3339),
		"target":     s.target,
	}

	// 执行每个匹配器
	for _, matcher := range template.Matchers {
		matched, err := s.executeMatcher(ctx, matcher)
		if err != nil {
			details["matcher_error"] = err.Error()
			return false, details, err
		}
		if matched {
			details["matched_matcher"] = matcher.Type
			return true, details, nil
		}
	}

	return false, details, nil
}

// executeMatcher 执行单个匹配器
func (s *Scanner) executeMatcher(ctx context.Context, matcher Matcher) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.target, nil)
	if err != nil {
		return false, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 根据匹配器类型执行不同的检查
	switch matcher.Type {
	case "status":
		for _, status := range matcher.Status {
			if resp.StatusCode == status {
				return !matcher.Inverse, nil
			}
		}
	case "header":
		// 实现header匹配逻辑
	case "body":
		// 实现body匹配逻辑
	}

	return matcher.Inverse, nil
}
