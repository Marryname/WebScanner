# GoSecScanner - Go语言网络安全扫描器

## 项目介绍
GoSecScanner 是一个基于 Go 语言开发的综合性网络安全扫描工具，提供端口扫描、子域名发现、CDN识别、存活探测、服务识别等功能。本工具适合网络安全人员进行安全评估使用。

## 主要功能
1. 端口扫描
   - TCP/UDP 端口扫描
   - 自定义端口范围
   - 多线程并发扫描
   
2. 子域名发现
   - DNS爆破
   - 证书透明度日志查询
   - 搜索引擎爬虫
   
3. CDN识别
   - CNAME记录检测
   - IP地理位置分析
   - TTL值检测
   
4. 存活探测
   - ICMP探测
   - TCP SYN探测
   - HTTP请求探测
   
5. 服务识别
   - 常见服务指纹库
   - Banner获取
   - 版本识别
   
6. 漏洞扫描
   - 内置漏洞模板
   - 自定义漏洞规则
   - 漏洞验证功能

## 项目结构
```
gosecscanner/
├── cmd/                              # 命令行工具
│   ├── gosecscanner/                 # 主程序
│   ├── test/                         # 基础测试工具
│   ├── cdntest/                      # CDN检测测试工具
│   ├── alivetest/                    # 存活探测测试工具
│   ├── fptest/                       # 服务识别测试工具
│   └── vulntest/                     # 漏洞扫描测试工具
├── internal/                         # 内部包
│   ├── portscan/                     # 端口扫描模块
│   ├── subdomain/                    # 子域名发现模块
│   ├── cdn/                          # CDN识别模块
│   ├── alive/                        # 存活探测模块
│   ├── fingerprint/                  # 服务识别模块
│   └── vulnscan/                     # 漏洞扫描模块
├── pkg/                              # 公共包
│   ├── common/                       # 通用功能
│   ├── logger/                       # 日志模块
│   └── utils/                        # 工具函数
├── configs/                          # 配置文件
├── scripts/                          # 脚本文件
└── docs/                             # 文档
```

## 安装说明

```bash
# 克隆项目
git clone https://github.com/Marryname/WebScanner.git

# 进入项目目录
cd WebScanner

# 安装依赖
go mod tidy

# 编译
go build -o gosecscanner ./cmd/gosecscanner
```

## 使用说明

```bash
# 显示帮助信息
./gosecscanner --help

# 执行完整扫描
./gosecscanner scan -t example.com

# 指定模块扫描
./gosecscanner scan -t example.com -m port,cdn,vuln

# 自定义参数
./gosecscanner scan -t example.com -p 1-1000 -n 200 --timeout 10
```

## 贡献指南

1. Fork 本仓库
2. 创建你的特性分支 (git checkout -b feature/AmazingFeature)
3. 提交你的更改 (git commit -m 'Add some AmazingFeature')
4. 推送到分支 (git push origin feature/AmazingFeature)
5. 开启一个 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件