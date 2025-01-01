.PHONY: build test clean

# 变量定义
BINARY=webscan
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d %H:%M:%S')
LDFLAGS=-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

# 默认目标
all: build

# 构建
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/WebScanner

# 测试
test:
	go test -v ./...

# 清理
clean:
	go clean
	rm -f $(BINARY)

# 运行
run:
	./$(BINARY)

# 安装依赖
deps:
	go mod download
	go mod tidy

# 生成文档
doc:
	godoc -http=:6060

# 代码检查
lint:
	golangci-lint run

# 构建Docker镜像
docker:
	docker build -t webscan:$(VERSION) .