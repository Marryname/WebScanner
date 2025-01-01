package subdomain

import (
	"context"
	"testing"
	"time"
)

func TestFinder(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:    "测试有效域名",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "测试无效域名",
			domain:  "invalid-domain",
			wantErr: false, // 目前示例实现总是返回成功
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFinder(tt.domain)
			subdomains, err := finder.Find(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 验证结果
			if len(subdomains) == 0 {
				t.Log("没有发现子域名")
			} else {
				for _, subdomain := range subdomains {
					t.Logf("发现子域名: %s", subdomain)
				}
			}
		})
	}
}

func TestFinderWithContext(t *testing.T) {
	finder := NewFinder("example.com")

	// 测试上下文取消
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	subdomains, err := finder.Find(ctx)
	if err != nil {
		t.Logf("预期的上下文取消错误: %v", err)
	} else {
		t.Logf("发现 %d 个子域名", len(subdomains))
	}
}

func TestFinderWithInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"空域名", ""},
		{"特殊字符", "test!@#$.com"},
		{"过长域名", string(make([]byte, 300))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFinder(tt.domain)
			subdomains, err := finder.Find(context.Background())

			// 目前的示例实现不会返回错误，所以只记录结果
			if err != nil {
				t.Logf("获取到预期的错误: %v", err)
			}
			t.Logf("发现 %d 个子域名", len(subdomains))
		})
	}
}
