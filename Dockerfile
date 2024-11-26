# 使用官方的 Golang 镜像作为基础镜像
FROM golang:1.20-alpine

# 设置工作目录
WORKDIR /app

# 复制当前目录下的所有文件到工作目录
COPY . .

# 编译 Go 应用
RUN go build -o proxy-server

# 设置环境变量
ENV KEY_PREFIX=dsadsafasf

# 暴露应用运行的端口
EXPOSE 9888

# 运行应用
CMD ["./proxy-server"]