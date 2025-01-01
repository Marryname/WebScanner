# WebScanner

WebScanner 是一个功能强大的 Web 安全扫描工具，提供端口扫描、服务识别、漏洞扫描等多种安全检测功能。

## 主要功能

- 🔍 **端口扫描**：快速识别目标主机开放端口
- 🌐 **子域名发现**：自动发现和枚举子域名
- 🛡️ **CDN 检测**：检测目标是否使用 CDN 服务
- ⚡ **存活探测**：快速检测主机存活状态
- 🔎 **服务识别**：准确识别服务类型和版本
- 🚨 **漏洞扫描**：检测常见 Web 安全漏洞

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/Marryname/WebScanner.git

# 进入项目目录
cd WebScanner

# 安装依赖
make deps

# 编译项目
make build
```

### 基本使用

```bash
# 显示帮助信息
./webscan --help

# 执行完整扫描
./webscan scan -t example.com

# 指定特定模块扫描
./webscan scan -t example.com -m port,cdn,vuln

# 自定义扫描参数
./webscan scan -t example.com -p 1-1000 -n 200 --timeout 10 -o report.json
```

### Docker 运行

```bash
# 构建镜像
docker build -t webscan .

# 运行扫描
docker run webscan scan -t example.com
```

## 配置说明

配置文件支持 YAML、JSON、TOML 格式，默认配置文件路径：
- ./config.yaml
- $HOME/.webscan/config.yaml
- /etc/webscan/config.yaml

示例配置：

```yaml
scanner:
  timeout: 30
  threads: 100
  retry: 3

ports:
  default_range: "1-1000"
  common_ports: [21,22,23,25,53,80,443,3306,8080]

fingerprint:
  signatures_path: "configs/signatures"
  timeout: 5

vulnscan:
  templates_path: "configs/templates"
  concurrent: 10
  timeout: 30

logging:
  level: "info"
  file: "logs/scanner.log"
  format: "json"
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

## 开发指南

### 项目结构

```
.
├── cmd/                # 命令行工具
│   ├── WebScanner/    # 主程序
│   ├── alivetest/     # 存活探测测试
│   └── fptest/        # 服务识别测试
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
4. 添加测试代码
5. 更新配置文件

### 测试

```bash
# 运行所有测试
make test

# 运行特定模块测试
go test ./internal/fingerprint/...

# 运行基准测试
go test -bench=. ./...
```

## 独立测试工具

```bash
# 存活探测测试
go run cmd/alivetest/main.go -target example.com

# 服务识别测试
go run cmd/fptest/main.go -target example.com
```

## 常见问题

1. **扫描速度慢**
   - 调整并发数 (-n 参数)
   - 减少扫描端口范围
   - 使用 SYN 扫描模式

2. **误报问题**
   - 更新漏洞模板
   - 调整检测阈值
   - 使用白名单

3. **内存占用高**
   - 调整并发数
   - 使用增量扫描
   - 开启结果流式处理

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 安全说明

本工具仅用于安全测试，请勿用于非法用途。使用本工具进行测试时，请确保：

1. 获得测试目标的授权
2. 遵守相关法律法规
3. 不影响目标系统的正常运行
4. 及时报告发现的安全问题

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 作者

- Marryname

## 致谢

感谢以下开源项目：
- [cobra](https://github.com/spf13/cobra)
- [viper](https://github.com/spf13/viper)