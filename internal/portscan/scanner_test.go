package portscan

import (
	"testing"
	"time"
)

func TestPortScanner(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		start   int
		end     int
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "扫描本地主机常用端口",
			target:  "localhost",
			start:   20,
			end:     100,
			timeout: 2 * time.Second,
			wantErr: false,
		},
		{
			name:    "扫描公共服务器",
			target:  "scanme.nmap.org",
			start:   20,
			end:     100,
			timeout: 5 * time.Second,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewPortScanner(tt.target, tt.timeout)
			results := scanner.ParallelScan(tt.start, tt.end, 10)

			t.Logf("目标 %s 开放端口:", tt.target)
			for _, result := range results {
				t.Logf("端口 %d: %s", result.Port, result.State)
			}
		})
	}
}
