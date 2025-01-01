package alive

import (
	"testing"
	"time"
)

func TestAliveDetector(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		timeout    time.Duration
		concurrent int
		wantAlive  bool
		wantErr    bool
	}{
		{
			name:       "测试本地主机",
			target:     "localhost",
			timeout:    2 * time.Second,
			concurrent: 10,
			wantAlive:  true,
			wantErr:    false,
		},
		{
			name:       "测试公共DNS服务器",
			target:     "8.8.8.8",
			timeout:    5 * time.Second,
			concurrent: 10,
			wantAlive:  true,
			wantErr:    false,
		},
		{
			name:       "测试百度服务器",
			target:     "www.baidu.com",
			timeout:    5 * time.Second,
			concurrent: 10,
			wantAlive:  true,
			wantErr:    false,
		},
		{
			name:       "测试不存在的主机",
			target:     "not.exist.example.com",
			timeout:    2 * time.Second,
			concurrent: 10,
			wantAlive:  false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(tt.target, tt.timeout, tt.concurrent)
			result, err := detector.Detect()

			if (err != nil) != tt.wantErr {
				t.Errorf("错误状态不符合预期: %v", err)
				return
			}

			t.Logf("目标: %s", tt.target)
			t.Logf("存活状态: %v", result.IsAlive)
			t.Logf("探测方法: %v", result.Methods)
			if result.Error != nil {
				t.Logf("错误信息: %v", result.Error)
			}

			if result.IsAlive != tt.wantAlive {
				t.Errorf("存活状态不符合预期, 期望: %v, 实际: %v", tt.wantAlive, result.IsAlive)
			}
		})
	}
}

// TestIndividualMethods 测试各个探测方法
func TestIndividualMethods(t *testing.T) {
	detector := NewDetector("www.baidu.com", 5*time.Second, 10)

	// 测试ICMP探测
	t.Run("ICMP探测", func(t *testing.T) {
		alive, err := detector.icmpDetect()
		t.Logf("ICMP探测结果: %v, 错误: %v", alive, err)
	})

	// 测试TCP探测
	t.Run("TCP探测", func(t *testing.T) {
		alive, err := detector.tcpDetect()
		t.Logf("TCP探测结果: %v, 错误: %v", alive, err)
	})

	// 测试HTTP探测
	t.Run("HTTP探测", func(t *testing.T) {
		alive, err := detector.httpDetect()
		t.Logf("HTTP探测结果: %v, 错误: %v", alive, err)
	})
}
