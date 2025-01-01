package utils

import (
	"sync"
)

// ConcurrencyLimiter 并发限制器
type ConcurrencyLimiter struct {
	limit  int
	tokens chan struct{}
	wg     sync.WaitGroup
}

// NewConcurrencyLimiter 创建新的并发限制器
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		limit:  limit,
		tokens: make(chan struct{}, limit),
	}
}

// Execute 执行受限制的并发任务
func (l *ConcurrencyLimiter) Execute(fn func()) {
	l.tokens <- struct{}{} // 获取令牌
	l.wg.Add(1)

	go func() {
		defer func() {
			<-l.tokens // 释放令牌
			l.wg.Done()
		}()
		fn()
	}()
}

// Wait 等待所有任务完成
func (l *ConcurrencyLimiter) Wait() {
	l.wg.Wait()
}
