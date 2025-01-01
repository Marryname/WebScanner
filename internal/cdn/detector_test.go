package cdn

import (
	"testing"
)

func TestCDNDetector(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		expectCDN  bool
		wantCNAME  bool
		wantTTL    bool
		wantGeoLoc bool
	}{
		{
			name:       "测试使用CDN的网站 - Cloudflare",
			target:     "www.cloudflare.com",
			expectCDN:  true,
			wantCNAME:  true,
			wantTTL:    true,
			wantGeoLoc: true,
		},
		{
			name:       "测试使用CDN的网站 - 百度",
			target:     "www.baidu.com",
			expectCDN:  true,
			wantCNAME:  true,
			wantTTL:    true,
			wantGeoLoc: true,
		},
		{
			name:       "测试可能不使用CDN的网站",
			target:     "www.example.com",
			expectCDN:  false,
			wantCNAME:  false,
			wantTTL:    true,
			wantGeoLoc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(tt.target)
			info, err := detector.Detect()
			if err != nil {
				t.Errorf("CDN检测失败: %v", err)
				return
			}

			t.Logf("目标: %s", tt.target)
			t.Logf("是否使用CDN: %v", info.IsCDN)
			t.Logf("CNAME记录: %v", info.CNAMEs)
			t.Logf("IP地址: %v", info.IPs)
			t.Logf("TTL值: %d", info.TTL)
			t.Logf("地理位置: %v", info.GeoLocation)

			if info.IsCDN != tt.expectCDN {
				t.Errorf("CDN检测结果不符合预期, 期望: %v, 实际: %v", tt.expectCDN, info.IsCDN)
			}

			if tt.wantCNAME && len(info.CNAMEs) == 0 {
				t.Errorf("期望获取到CNAME记录但未获取到")
			}

			if tt.wantTTL && info.TTL == 0 {
				t.Errorf("期望获取到TTL值但未获取到")
			}

			if tt.wantGeoLoc && len(info.GeoLocation) == 0 {
				t.Errorf("期望获取到地理位置信息但未获取到")
			}
		})
	}
}

// TestCDNKeywords 测试CDN关键字匹配
func TestCDNKeywords(t *testing.T) {
	tests := []struct {
		cname    string
		expectIn bool
	}{
		{"cdn.cloudflare.net", true},
		{"cdn.fastly.net", true},
		{"akamai.net", true},
		{"cdn.amazonaws.com", true},
		{"kunlun.com", true},
		{"regular-domain.com", false},
		{"example.com", false},
	}

	detector := NewDetector("example.com")
	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			isMatch := detector.matchCDNPattern(tt.cname)
			if isMatch != tt.expectIn {
				t.Errorf("CNAME %s 匹配结果不符合预期, 期望: %v, 实际: %v",
					tt.cname, tt.expectIn, isMatch)
			}
		})
	}
}
