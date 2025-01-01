package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Template 漏洞模板结构
type Template struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Solution    string                 `json:"solution"`
	References  []string               `json:"references"`
	Matchers    []Matcher              `json:"matchers"`
	Payloads    map[string][]string    `json:"payloads"`
	Variables   map[string]string      `json:"variables"`
	Conditions  map[string]interface{} `json:"conditions"`
}

// Matcher 匹配器结构
type Matcher struct {
	Type    string   `json:"type"`
	Part    string   `json:"part"`
	Words   []string `json:"words,omitempty"`
	Regex   []string `json:"regex,omitempty"`
	Status  []int    `json:"status,omitempty"`
	Binary  bool     `json:"binary,omitempty"`
	Inverse bool     `json:"inverse,omitempty"`
}

// TemplateManager 模板管理器
type TemplateManager struct {
	templates map[string]*Template
}

// NewTemplateManager 创建新的模板管理器
func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*Template),
	}
}

// LoadTemplates 从目录加载模板
func (tm *TemplateManager) LoadTemplates(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			template, err := tm.loadTemplate(path)
			if err != nil {
				return fmt.Errorf("加载模板失败 %s: %v", path, err)
			}
			tm.templates[template.ID] = template
		}

		return nil
	})
}

// loadTemplate 加载单个模板文件
func (tm *TemplateManager) loadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var template Template
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}

	return &template, nil
}

// GetTemplates 获取所有模板
func (tm *TemplateManager) GetTemplates() []*Template {
	var templates []*Template
	for _, t := range tm.templates {
		templates = append(templates, t)
	}
	return templates
}

// IsApplicable 检查模板是否适用于目标
func (t *Template) IsApplicable(target string) bool {
	if conditions, ok := t.Conditions["target"]; ok {
		switch v := conditions.(type) {
		case string:
			matched, _ := regexp.MatchString(v, target)
			return matched
		case []interface{}:
			for _, pattern := range v {
				if p, ok := pattern.(string); ok {
					matched, _ := regexp.MatchString(p, target)
					if matched {
						return true
					}
				}
			}
		}
		return false
	}
	return true
}

// Execute 执行模板检测
func (t *Template) Execute(ctx context.Context, client *http.Client, target string) (bool, map[string]interface{}, error) {
	details := make(map[string]interface{})

	for _, matcher := range t.Matchers {
		matched, err := t.executeMatcher(ctx, client, target, matcher)
		if err != nil {
			return false, nil, err
		}

		if matched {
			details["matcher_type"] = matcher.Type
			details["matched_part"] = matcher.Part
			return true, details, nil
		}
	}

	return false, nil, nil
}

// executeMatcher 执行匹配器
func (t *Template) executeMatcher(ctx context.Context, client *http.Client, target string, matcher Matcher) (bool, error) {
	switch matcher.Type {
	case "http":
		return t.executeHTTPMatcher(ctx, client, target, matcher)
	case "regex":
		return t.executeRegexMatcher(target, matcher)
	case "binary":
		return t.executeBinaryMatcher(target, matcher)
	default:
		return false, fmt.Errorf("不支持的匹配器类型: %s", matcher.Type)
	}
}

// executeHTTPMatcher 执行HTTP匹配器
func (t *Template) executeHTTPMatcher(ctx context.Context, client *http.Client, target string, matcher Matcher) (bool, error) {
	// 构建请求URL
	url := target
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// 根据匹配部分进行检查
	switch matcher.Part {
	case "body":
		return t.matchContent(string(body), matcher)
	case "header":
		return t.matchHeaders(resp.Header, matcher)
	case "status":
		return t.matchStatus(resp.StatusCode, matcher)
	default:
		return false, fmt.Errorf("不支持的匹配部分: %s", matcher.Part)
	}
}

// executeRegexMatcher 执行正则表达式匹配器
func (t *Template) executeRegexMatcher(target string, matcher Matcher) (bool, error) {
	if len(matcher.Regex) == 0 {
		return false, nil
	}

	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("正则表达式编译失败: %v", err)
		}

		if re.MatchString(target) {
			if matcher.Inverse {
				return false, nil
			}
			return true, nil
		}
	}

	if matcher.Inverse {
		return true, nil
	}
	return false, nil
}

// executeBinaryMatcher 执行二进制匹配器
func (t *Template) executeBinaryMatcher(target string, matcher Matcher) (bool, error) {
	if len(matcher.Words) == 0 {
		return false, nil
	}

	data := []byte(target)
	for _, word := range matcher.Words {
		if bytes.Contains(data, []byte(word)) {
			if matcher.Inverse {
				return false, nil
			}
			return true, nil
		}
	}

	if matcher.Inverse {
		return true, nil
	}
	return false, nil
}

// matchContent 匹配内容
func (t *Template) matchContent(content string, matcher Matcher) (bool, error) {
	if len(matcher.Words) > 0 {
		for _, word := range matcher.Words {
			if strings.Contains(content, word) != matcher.Inverse {
				return true, nil
			}
		}
	}

	if len(matcher.Regex) > 0 {
		for _, pattern := range matcher.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false, err
			}
			if re.MatchString(content) != matcher.Inverse {
				return true, nil
			}
		}
	}

	return false, nil
}

// matchHeaders 匹配HTTP头
func (t *Template) matchHeaders(headers http.Header, matcher Matcher) (bool, error) {
	for _, word := range matcher.Words {
		for key, values := range headers {
			for _, value := range values {
				if strings.Contains(key, word) || strings.Contains(value, word) {
					return !matcher.Inverse, nil
				}
			}
		}
	}

	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		for key, values := range headers {
			for _, value := range values {
				if re.MatchString(key) || re.MatchString(value) {
					return !matcher.Inverse, nil
				}
			}
		}
	}

	return matcher.Inverse, nil
}

// matchStatus 匹配HTTP状态码
func (t *Template) matchStatus(statusCode int, matcher Matcher) (bool, error) {
	if len(matcher.Status) == 0 {
		return false, nil
	}

	for _, status := range matcher.Status {
		if status == statusCode {
			return !matcher.Inverse, nil
		}
	}

	return matcher.Inverse, nil
}
