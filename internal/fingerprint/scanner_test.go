package fingerprint

import (
	"context"
	"testing"
	"time"
)

func TestScanner(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "测试HTTP服务",
			target:  "localhost",
			timeout: 5 * time.Second,
			wantErr: false,
		},
		{
			name:    "测试HTTPS服务",
			target:  "example.com",
			timeout: 5 * time.Second,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(tt.target, tt.timeout)
			results, err := scanner.Scan(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(results) > 0 {
				for _, result := range results {
					t.Logf("识别到服务: %s (端口: %d)", result.ServiceName, result.Port)
				}
			}
		})
	}
}
