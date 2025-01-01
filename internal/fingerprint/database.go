package fingerprint

import (
	"regexp"
	"strings"
)

// Database 服务识别数据库
type Database struct {
	servicePatterns map[string][]string
	versionPatterns map[string]*regexp.Regexp
}

// NewDatabase 创建新的服务识别数据库
func NewDatabase() *Database {
	db := &Database{
		servicePatterns: make(map[string][]string),
		versionPatterns: make(map[string]*regexp.Regexp),
	}

	// 初始化服务识别模式
	db.initServicePatterns()
	db.initVersionPatterns()

	return db
}

// initServicePatterns 初始化服务识别模式
func (db *Database) initServicePatterns() {
	db.servicePatterns = map[string][]string{
		"HTTP":    {"HTTP", "Server:", "Apache", "nginx", "IIS"},
		"SSH":     {"SSH", "OpenSSH"},
		"FTP":     {"FTP", "FileZilla", "vsftpd"},
		"SMTP":    {"SMTP", "Postfix", "Exchange"},
		"MySQL":   {"MySQL"},
		"Redis":   {"Redis"},
		"MongoDB": {"MongoDB"},
	}
}

// initVersionPatterns 初始化版本识别模式
func (db *Database) initVersionPatterns() {
	patterns := map[string]string{
		"Apache": `Apache/(\d+\.\d+\.\d+)`,
		"nginx":  `nginx/(\d+\.\d+\.\d+)`,
		"SSH":    `OpenSSH_(\d+\.\d+\w*)`,
	}

	for name, pattern := range patterns {
		db.versionPatterns[name] = regexp.MustCompile(pattern)
	}
}

// IdentifyService 识别服务类型
func (db *Database) IdentifyService(port int, banner string) string {
	// 根据端口判断
	switch port {
	case 80, 443:
		return "HTTP"
	case 22:
		return "SSH"
	case 21:
		return "FTP"
	case 25:
		return "SMTP"
	case 3306:
		return "MySQL"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	}

	// 根据banner判断
	if banner != "" {
		banner = strings.ToUpper(banner)
		for service, patterns := range db.servicePatterns {
			for _, pattern := range patterns {
				if strings.Contains(banner, strings.ToUpper(pattern)) {
					return service
				}
			}
		}
	}

	return "Unknown"
}

// IdentifyVersion 识别服务版本
func (db *Database) IdentifyVersion(banner string) string {
	if banner == "" {
		return ""
	}

	for _, pattern := range db.versionPatterns {
		if matches := pattern.FindStringSubmatch(banner); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}
