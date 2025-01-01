# 构建阶段
FROM golang:1.19-alpine AS builder

WORKDIR /app

# 安装依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o webscan ./cmd/WebScanner

# 运行阶段
FROM alpine:latest

WORKDIR /app

# 复制配置文件和可执行文件
COPY --from=builder /app/webscan .
COPY --from=builder /app/configs ./configs

# 创建必要的目录
RUN mkdir -p /app/logs

# 设置环境变量
ENV PATH="/app:${PATH}"

# 暴露端口
EXPOSE 8080

# 运行命令
ENTRYPOINT ["/app/webscan"]
CMD ["--help"]