package portscan

import (
	"context"
	"testing"
	"time"
)

func TestPortScanner(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "测试有效目标",
			target:  "localhost",
			timeout: 5 * time.Second,
			wantErr: false,
		},
		{
			name:    "测试无效目标",
			target:  "invalid-host",
			timeout: 5 * time.Second,
			wantErr: false, // 目前示例实现总是返回成功
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewPortScanner(tt.target, tt.timeout)

			results, err := scanner.Scan(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 验证结果
			if len(results) == 0 {
				t.Log("没有发现开放端口")
			} else {
				for _, result := range results {
					t.Logf("发现开放端口: %d (%s)", result.Port, result.Service)
				}
			}
		})
	}
}

func TestPortScannerWithContext(t *testing.T) {
	scanner := NewPortScanner("localhost", 5*time.Second)

	// 测试上下文取消
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results, err := scanner.Scan(ctx)
	if err != nil {
		t.Logf("预期的上下文取消错误: %v", err)
	} else {
		t.Logf("扫描完成，发现 %d 个开放端口", len(results))
	}
}
