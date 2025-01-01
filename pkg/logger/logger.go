package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

type Logger struct {
	level     Level
	file      *os.File
	isConsole bool
}

func NewLogger(level Level, logPath string, console bool) (*Logger, error) {
	logger := &Logger{
		level:     level,
		isConsole: console,
	}

	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
			return nil, err
		}

		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		logger.file = file
	}

	return logger, nil
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	levelStr := [...]string{"DEBUG", "INFO", "WARN", "ERROR"}
	msg := fmt.Sprintf("%s [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		levelStr[level],
		fmt.Sprintf(format, args...))

	if l.isConsole {
		fmt.Print(msg)
	}

	if l.file != nil {
		l.file.WriteString(msg)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
