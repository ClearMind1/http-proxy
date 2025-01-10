# 构建阶段
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o proxy-server

# 运行阶段
FROM alpine:latest

WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/proxy-server .

ENV KEY_PREFIX=dsadsafasf
ENV ENABLE_RATE_LIMIT=true

EXPOSE 9888

CMD ["./proxy-server"]