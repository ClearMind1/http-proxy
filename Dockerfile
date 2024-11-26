# 使用官方的 Golang 镜像作为基础镜像
FROM golang:1.23-alpine

# 设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum 文件（如果存在）
COPY go.mod ./
COPY go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 编译 Go 应用
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy-server

# 设置环境变量
ENV KEY_PREFIX=dsadsafasf

# 暴露应用运行的端口
EXPOSE 9888

# 运行应用
CMD ["./proxy-server"]