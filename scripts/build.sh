#!/bin/bash

# 设置版本信息
VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date +%FT%T%z)

# 构建标志
LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME"

# 清理旧的构建文件
rm -rf build/
mkdir -p build/

# 构建主程序
echo "Building main scanner..."
go build -ldflags "$LDFLAGS" -o build/gosecscanner ./cmd/gosecscanner

# 构建测试工具
echo "Building test tools..."
for tool in test cdntest alivetest fptest vulntest; do
    echo "Building $tool..."
    go build -o build/$tool ./cmd/$tool
done

echo "Build complete!" 