package vulnscan

import (
	"encoding/json"
	"html/template"
	"os"
	"time"
)

// Report 扫描报告结构
type Report struct {
	Target     string        `json:"target"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	TotalVulns int           `json:"total_vulns"`
	Results    []*VulnResult `json:"results"`
	Summary    ReportSummary `json:"summary"`
}

// ReportSummary 报告摘要
type ReportSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// NewReport 创建新的扫描报告
func NewReport(target string, results []*VulnResult, startTime time.Time) *Report {
	report := &Report{
		Target:    target,
		StartTime: startTime,
		EndTime:   time.Now(),
		Results:   results,
	}

	report.Duration = report.EndTime.Sub(report.StartTime)
	report.TotalVulns = len(results)
	report.generateSummary()

	return report
}

// generateSummary 生成报告摘要
func (r *Report) generateSummary() {
	for _, result := range r.Results {
		switch result.Severity {
		case "critical":
			r.Summary.Critical++
		case "high":
			r.Summary.High++
		case "medium":
			r.Summary.Medium++
		case "low":
			r.Summary.Low++
		default:
			r.Summary.Info++
		}
	}
}

// SaveJSON 保存JSON格式报告
func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// SaveHTML 保存HTML格式报告
func (r *Report) SaveHTML(path string) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, r)
}

// reportTemplate HTML报告模板
const reportTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>漏洞扫描报告 - {{.Target}}</title>
    <style>
        /* 添加CSS样式 */
    </style>
</head>
<body>
    <h1>漏洞扫描报告</h1>
    <h2>目标: {{.Target}}</h2>
    <div class="summary">
        <h3>扫描摘要</h3>
        <p>开始时间: {{.StartTime}}</p>
        <p>结束时间: {{.EndTime}}</p>
        <p>扫描时长: {{.Duration}}</p>
        <p>发现漏洞: {{.TotalVulns}}</p>
    </div>
    <div class="results">
        <h3>漏洞详情</h3>
        {{range .Results}}
        <div class="vuln-item severity-{{.Severity}}">
            <h4>{{.Name}} ({{.VulnID}})</h4>
            <p>严重级别: {{.Severity}}</p>
            <p>描述: {{.Description}}</p>
            <p>解决方案: {{.Solution}}</p>
        </div>
        {{end}}
    </div>
</body>
</html>
`
