# WebScanner

WebScanner 是一个功能完整的 Web 安全扫描工具，提供端口扫描、服务识别、漏洞扫描等功能。

## 功能特点

- 端口扫描：快速识别开放端口
- 子域名发现：发现目标域名的子域名
- CDN 检测：检测目标是否使用 CDN 服务
- 存活探测：检测主机存活状态
- 服务识别：识别服务类型和版本
- 漏洞扫描：检测常见安全漏洞

## 安装

```bash
# 克隆仓库
git clone https://github.com/Marryname/WebScanner.git

# 进入目录
cd WebScanner

# 安装依赖
go mod download

# 编译
go build -o webscan cmd/WebScanner/main.go
```

## 使用方法

### 主程序

```bash
# 显示帮助信息
./webscan --help

# 执行扫描
./webscan scan -t example.com

# 指定特定模块
./webscan scan -t example.com -m port,cdn,vuln

# 使用更多选项
./webscan scan -t example.com -p 1-1000 -n 200 --timeout 10 -o report.json
```

### 独立测试工具

```bash
# 端口扫描测试
go run cmd/porttest/main.go -target example.com

# CDN检测测试
go run cmd/cdntest/main.go -target example.com

# 存活探测测试
go run cmd/alivetest/main.go -target example.com

# 服务识别测试
go run cmd/fptest/main.go -target example.com

# 漏洞扫描测试
go run cmd/vulntest/main.go -target example.com
```

## 配置文件

配置文件支持 YAML、JSON、TOML 格式，默认搜索以下位置：
- ./config.yaml
- $HOME/.webscan/config.yaml
- /etc/webscan/config.yaml

示例配置：

```yaml
scanner:
  threads: 100
  timeout: 5
  ports: "1-1000"

logging:
  level: info
  file: "scan.log"

modules:
  - port
  - cdn
  - vuln
```

## 命令行参数

```
全局参数:
  --config string     配置文件路径
  --log-level string  日志级别 (debug|info|warn|error)
  --log-file string   日志文件路径
  -v, --version      显示版本信息

扫描参数:
  -t, --target string   扫描目标 (必需)
  -p, --ports string    端口范围 (默认 "1-1000")
  -n, --threads int     并发线程数 (默认 100)
  --timeout int         超时时间(秒) (默认 5)
  -m, --modules string  扫描模块 (port|subdomain|cdn|alive|finger|vuln|all)
  -o, --output string   输出文件路径
```

## 输出格式

扫描结果支持 JSON 和 HTML 格式输出，包含以下信息：
- 基本信息（目标、时间等）
- 端口扫描结果
- 服务识别结果
- 漏洞扫描结果
- 统计信息

## 开发说明

### 项目结构

```
.
├── cmd/                # 命令行工具
│   ├── WebScanner/    # 主程序
│   ├── alivetest/     # 存活探测测试
│   ├── cdntest/       # CDN检测测试
│   ├── fptest/        # 服务识别测试
│   ├── porttest/      # 端口扫描测试
│   └── vulntest/      # 漏洞扫描测试
├── internal/          # 内部包
│   ├── alive/        # 存活探测
│   ├── cdn/          # CDN检测
│   ├── fingerprint/  # 服务识别
│   ├── portscan/     # 端口扫描
│   ├── subdomain/    # 子域名发现
│   └── vulnscan/     # 漏洞扫描
├── pkg/              # 公共包
│   └── logger/       # 日志工具
└── configs/          # 配置文件
    └── templates/    # 漏洞模板
```

### 添加新模块

1. 在 internal/ 下创建新模块目录
2. 实现模块接口
3. 在 cmd/WebScanner/scan.go 中添加模块支持
4. 添加测试程序（可选）

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 作者

- Marryname

## 致谢

感谢以下开源项目：
- [cobra](https://github.com/spf13/cobra)
- [viper](https://github.com/spf13/viper)