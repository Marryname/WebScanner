package vulnscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanner(t *testing.T) {
	// 创建测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "Apache/2.4.41")
			w.Write([]byte("<title>Test Page</title>"))
		case "/test.php":
			w.Write([]byte("<?php phpinfo(); ?>"))
		}
	}))
	defer ts.Close()

	// 创建临时模板目录
	tempDir := t.TempDir()
	createTestTemplates(t, tempDir)

	tests := []struct {
		name       string
		target     string
		timeout    time.Duration
		concurrent int
		wantErr    bool
	}{
		{
			name:       "基本扫描测试",
			target:     ts.URL,
			timeout:    5 * time.Second,
			concurrent: 2,
			wantErr:    false,
		},
		{
			name:       "超时测试",
			target:     "http://localhost:1",
			timeout:    100 * time.Millisecond,
			concurrent: 1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(tt.target, tt.timeout, tt.concurrent)
			err := scanner.LoadTemplates(tempDir)
			if err != nil {
				t.Fatalf("加载模板失败: %v", err)
			}

			results, err := scanner.Scan(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				t.Logf("扫描完成，发现 %d 个漏洞", len(results))
				for _, result := range results {
					t.Logf("漏洞: %s (%s)", result.Name, result.Severity)
				}
			}
		})
	}
}

func TestScannerWithContext(t *testing.T) {
	scanner := NewScanner("http://example.com", 5*time.Second, 2)

	// 创建一个会立即取消的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	results, err := scanner.Scan(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("期望上下文超时错误，得到: %v", err)
	}

	t.Logf("扫描被取消，返回 %d 个结果", len(results))
}

func TestScannerWithInvalidTemplates(t *testing.T) {
	scanner := NewScanner("http://example.com", 5*time.Second, 2)

	// 测试加载不存在的模板目录
	err := scanner.LoadTemplates("non-existent-dir")
	if err == nil {
		t.Error("期望加载不存在的目录时返回错误")
	}

	// 测试加载无效的模板文件
	tempDir := t.TempDir()
	invalidTemplate := filepath.Join(tempDir, "invalid.json")
	os.WriteFile(invalidTemplate, []byte("invalid json"), 0644)

	err = scanner.LoadTemplates(tempDir)
	if err == nil {
		t.Error("期望加载无效模板时返回错误")
	}
}

// createTestTemplates 创建测试用的模板文件
func createTestTemplates(t *testing.T, dir string) {
	templates := []struct {
		name     string
		content  string
		wantErr  bool
		template Template
	}{
		{
			name: "test1.json",
			template: Template{
				ID:          "TEST-001",
				Name:        "测试漏洞1",
				Description: "这是一个测试漏洞",
				Severity:    "High",
				Solution:    "升级到最新版本",
				Matchers: []Matcher{
					{
						Type:  "word",
						Words: []string{"test"},
					},
				},
			},
		},
		{
			name: "test2.json",
			template: Template{
				ID:          "TEST-002",
				Name:        "测试漏洞2",
				Description: "另一个测试漏洞",
				Severity:    "Medium",
				Solution:    "修改配置",
				Matchers: []Matcher{
					{
						Type:  "regex",
						Regex: []string{`php`},
					},
				},
			},
		},
	}

	for _, tmpl := range templates {
		content, err := json.MarshalIndent(tmpl.template, "", "  ")
		if err != nil {
			t.Fatalf("创建测试模板失败: %v", err)
		}

		err = os.WriteFile(filepath.Join(dir, tmpl.name), content, 0644)
		if err != nil {
			t.Fatalf("写入测试模板失败: %v", err)
		}
	}
}
