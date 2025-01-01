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
			name:    "测试有效目标",
			target:  "example.com",
			timeout: 5 * time.Second,
			wantErr: false,
		},
		{
			name:    "测试无效目标",
			target:  "invalid.domain.test",
			timeout: 5 * time.Second,
			wantErr: true,
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

			if !tt.wantErr && len(results) == 0 {
				t.Error("Scan() returned no results for valid target")
			}
		})
	}
}

func TestDatabase(t *testing.T) {
	db := NewDatabase()

	tests := []struct {
		name    string
		port    int
		banner  string
		want    string
		wantVer string
	}{
		{
			name:    "HTTP服务识别",
			port:    80,
			banner:  "Apache/2.4.41 (Ubuntu)",
			want:    "HTTP",
			wantVer: "2.4.41",
		},
		{
			name:    "SSH服务识别",
			port:    22,
			banner:  "OpenSSH_8.2p1 Ubuntu-4ubuntu0.2",
			want:    "SSH",
			wantVer: "8.2p1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := db.IdentifyService(tt.port, tt.banner); got != tt.want {
				t.Errorf("IdentifyService() = %v, want %v", got, tt.want)
			}

			if got := db.IdentifyVersion(tt.banner); got != tt.wantVer {
				t.Errorf("IdentifyVersion() = %v, want %v", got, tt.wantVer)
			}
		})
	}
}
