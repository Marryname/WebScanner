package vulnscan

import (
	"encoding/json"
	"os"
	"time"
)

type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

type Report struct {
	Target     string
	StartTime  time.Time
	Duration   time.Duration
	TotalVulns int
	Summary    Summary
	Results    []VulnResult
}

func NewReport(target string, results []VulnResult, startTime time.Time) *Report {
	report := &Report{
		Target:     target,
		StartTime:  startTime,
		Duration:   time.Since(startTime),
		TotalVulns: len(results),
		Results:    results,
	}

	// 统计各级别漏洞数量
	for _, result := range results {
		switch result.Severity {
		case "Critical":
			report.Summary.Critical++
		case "High":
			report.Summary.High++
		case "Medium":
			report.Summary.Medium++
		case "Low":
			report.Summary.Low++
		case "Info":
			report.Summary.Info++
		}
	}

	return report
}

func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (r *Report) SaveHTML(path string) error {
	// 临时实现：将JSON内容保存为HTML
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	html := []byte("<pre>" + string(data) + "</pre>")
	return os.WriteFile(path, html, 0644)
}
