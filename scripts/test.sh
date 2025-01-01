#!/bin/bash

# 运行所有测试
echo "Running all tests..."
go test -v ./...

# 运行特定模块测试
run_module_test() {
    echo "Testing $1 module..."
    go test -v ./internal/$1
}

# 测试各个模块
run_module_test "portscan"
run_module_test "subdomain"
run_module_test "cdn"
run_module_test "alive"
run_module_test "fingerprint"
run_module_test "vulnscan"

echo "All tests completed!"