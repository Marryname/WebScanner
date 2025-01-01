package common

import (
	"time"
)

// Result 通用扫描结果结构
type Result struct {
	Target    string
	Status    Status
	Timestamp time.Time
	Duration  time.Duration
	Error     error
}

type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// Config 通用配置结构
type Config struct {
	Timeout    time.Duration
	Threads    int
	RetryCount int
	LogLevel   string
	LogFile    string
}
