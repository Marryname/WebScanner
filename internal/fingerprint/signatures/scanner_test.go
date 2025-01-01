package fingerprint

import (
	"fmt"
	"testing"
	"time"
)

func TestServiceScanner(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		port        int
		wantErr     bool
		wantBanner  bool
		wantService string
	}{
		{
			name:        "测试HTTP服务",
			target:      "www.baidu.com",
			port:        80,
			wantErr:     false,
			wantBanner:  true,
			wantService: "HTTP",
		},
		{
			name:        "测试HTTPS服务",
			target:      "www.baidu.com",
			port:        443,
			wantErr:     false,
			wantBanner:  true,
			wantService: "HTTP",
		},
		{
			name:        "测试SSH服务",
			target:      "github.com",
			port:        22,
			wantErr:     false,
			wantBanner:  true,
			wantService: "SSH",
		},
		{
			name:        "测试不存在的端口",
			target:      "localhost",
			port:        9999,
			wantErr:     true,
			wantBanner:  false,
			wantService: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(tt.target, 5*time.Second)
			info, err := scanner.ScanPort(tt.port)

			if (err != nil) != tt.wantErr {
				t.Errorf("错误状态不符合预期: %v", err)
				return
			}

			if err == nil {
				t.Logf("目标: %s:%d", tt.target, tt.port)
				t.Logf("服务: %s", info.ServiceName)
				t.Logf("版本: %s", info.Version)
				t.Logf("Banner: %s", info.Banner)
				t.Logf("额外信息: %v", info.Extra)

				if tt.wantBanner && info.Banner == "" {
					t.Errorf("期望获取到Banner但未获取到")
				}

				if tt.wantService != "" && info.ServiceName != tt.wantService {
					t.Errorf("服务识别结果不符合预期, 期望: %s, 实际: %s",
						tt.wantService, info.ServiceName)
				}
			}
		})
	}
}

// TestBannerGrabbing 测试Banner获取功能
func TestBannerGrabbing(t *testing.T) {
	scanner := NewScanner("www.baidu.com", 5*time.Second)

	tests := []struct {
		port    int
		wantErr bool
	}{
		{80, false},
		{443, false},
		{22, true},   // 可能被拒绝
		{9999, true}, // 不存在的端口
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Port_%d", tt.port), func(t *testing.T) {
			banner, err := scanner.grabBanner(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("端口 %d Banner获取错误状态不符合预期: %v", tt.port, err)
				return
			}

			if err == nil {
				t.Logf("端口 %d Banner: %s", tt.port, banner)
			}
		})
	}
}

// TestVersionDetection 测试版本识别功能
func TestVersionDetection(t *testing.T) {
	tests := []struct {
		banner      string
		wantVersion string
	}{
		{"Apache/2.4.41 (Unix)", "2.4.41"},
		{"nginx/1.18.0", "1.18.0"},
		{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.2", "8.2"},
		{"MySQL server version 5.7.33", "5.7.33"},
		{"No version info", ""},
	}

	scanner := NewScanner("example.com", time.Second)
	for _, tt := range tests {
		t.Run(tt.banner, func(t *testing.T) {
			info := &ServiceInfo{Banner: tt.banner}
			scanner.detectVersion(info)

			if info.Version != tt.wantVersion {
				t.Errorf("版本识别结果不符合预期, 期望: %s, 实际: %s",
					tt.wantVersion, info.Version)
			}
		})
	}
}
