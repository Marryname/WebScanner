package vulnscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVulnScanner(t *testing.T) {
	// 创建测试HTTP服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "Apache/2.4.41 (Unix)")
			w.Write([]byte("<title>Test Page</title>"))
		case "/phpinfo.php":
			w.Write([]byte("PHP Version 7.4.1"))
		case "/wp-login.php":
			w.Write([]byte("WordPress"))
		}
	}))
	defer ts.Close()

	tests := []struct {
		name      string
		target    string
		wantVulns bool
		templates []*Template
	}{
		{
			name:      "测试基本Web漏洞",
			target:    ts.URL,
			wantVulns: true,
			templates: []*Template{
				{
					ID:          "test-001",
					Name:        "PHP版本信息泄露",
					Description: "PHP版本信息可以被远程获取",
					Severity:    "low",
					Matchers: []Matcher{
						{
							Type:  "http",
							Part:  "body",
							Words: []string{"PHP Version"},
						},
					},
				},
				{
					ID:          "test-002",
					Name:        "WordPress登录页面",
					Description: "发现WordPress登录页面",
					Severity:    "info",
					Matchers: []Matcher{
						{
							Type:  "http",
							Part:  "body",
							Words: []string{"WordPress"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(tt.target, 5*time.Second, 10)
			scanner.templates.templates = make(map[string]*Template)

			// 添加测试模板
			for _, tmpl := range tt.templates {
				scanner.templates.templates[tmpl.ID] = tmpl
			}

			ctx := context.Background()
			results, err := scanner.Scan(ctx)
			if err != nil {
				t.Errorf("扫描失败: %v", err)
				return
			}

			t.Logf("发现 %d 个漏洞", len(results))
			for _, result := range results {
				t.Logf("漏洞ID: %s", result.VulnID)
				t.Logf("名称: %s", result.Name)
				t.Logf("严重级别: %s", result.Severity)
				t.Logf("描述: %s", result.Description)
			}

			if tt.wantVulns && len(results) == 0 {
				t.Error("期望发现漏洞但未发现")
			}
		})
	}
}

// TestTemplateMatching 测试模板匹配功能
func TestTemplateMatching(t *testing.T) {
	tests := []struct {
		name     string
		template *Template
		content  string
		want     bool
	}{
		{
			name: "测试正则匹配",
			template: &Template{
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{`PHP Version \d+\.\d+`},
					},
				},
			},
			content: "PHP Version 7.4.1",
			want:    true,
		},
		{
			name: "测试关键词匹配",
			template: &Template{
				Matchers: []Matcher{
					{
						Type:  "word",
						Words: []string{"admin", "password"},
					},
				},
			},
			content: "admin login password page",
			want:    true,
		},
		{
			name: "测试多条件匹配",
			template: &Template{
				Matchers: []Matcher{
					{
						Type:  "word",
						Words: []string{"login"},
					},
					{
						Type:  "regex",
						Regex: []string{`version \d+`},
					},
				},
			},
			content: "login page version 5",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Timeout: time.Second * 5}
			matched, _, err := tt.template.Execute(context.Background(), client, tt.content)
			if err != nil {
				t.Errorf("模板执行失败: %v", err)
				return
			}

			if matched != tt.want {
				t.Errorf("匹配结果不符合预期, 期望: %v, 实际: %v", tt.want, matched)
			}
		})
	}
}

// TestReportGeneration 测试报告生成功能
func TestReportGeneration(t *testing.T) {
	results := []*VulnResult{
		{
			VulnID:      "test-001",
			Name:        "测试漏洞1",
			Severity:    "high",
			Description: "这是一个测试漏洞",
			Solution:    "升级到最新版本",
			Timestamp:   time.Now(),
		},
		{
			VulnID:      "test-002",
			Name:        "测试漏洞2",
			Severity:    "medium",
			Description: "另一个测试漏洞",
			Solution:    "修改配置",
			Timestamp:   time.Now(),
		},
	}

	report := NewReport("test.com", results, time.Now())

	// 测试JSON报告生成
	t.Run("JSON报告", func(t *testing.T) {
		err := report.SaveJSON("test_report.json")
		if err != nil {
			t.Errorf("JSON报告生成失败: %v", err)
		}
	})

	// 测试HTML报告生成
	t.Run("HTML报告", func(t *testing.T) {
		err := report.SaveHTML("test_report.html")
		if err != nil {
			t.Errorf("HTML报告生成失败: %v", err)
		}
	})

	// 验证报告摘要
	t.Run("报告摘要", func(t *testing.T) {
		if report.TotalVulns != 2 {
			t.Errorf("漏洞总数不正确, 期望: 2, 实际: %d", report.TotalVulns)
		}
		if report.Summary.High != 1 {
			t.Errorf("高危漏洞数不正确, 期望: 1, 实际: %d", report.Summary.High)
		}
		if report.Summary.Medium != 1 {
			t.Errorf("中危漏洞数不正确, 期望: 1, 实际: %d", report.Summary.Medium)
		}
	})
}
