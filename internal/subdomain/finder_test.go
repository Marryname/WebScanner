package subdomain

import (
	"testing"
)

func TestSubdomainFinder(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   int // 期望找到的子域名最小数量
	}{
		{
			name:   "查找 baidu.com 的子域名",
			domain: "baidu.com",
			want:   1,
		},
		{
			name:   "查找 google.com 的子域名",
			domain: "google.com",
			want:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewSubdomainFinder(tt.domain)
			// 添加一些常用子域名前缀用于测试
			finder.wordlist = []string{
				"www", "mail", "ftp", "smtp", "pop",
				"api", "dev", "test", "admin", "blog",
			}

			results := finder.DNSBruteforce()
			t.Logf("域名 %s 发现的子域名:", tt.domain)
			for _, subdomain := range results {
				t.Logf("- %s", subdomain)
			}

			if len(results) < tt.want {
				t.Errorf("期望找到至少 %d 个子域名, 但只找到 %d 个", tt.want, len(results))
			}
		})
	}
}
