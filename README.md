
> 来自于claude 3.5 sonnet 生成
# Go HTTP 代理服务器

这是一个用 Go 语言编写的 HTTP 代理服务器，具有限流、重试、超时等功能。

## 主要特性

- 支持 HTTP/HTTPS 代理
- IP 级别限流（每IP每秒10个请求）
- 全局限流（每秒100个请求）
- 自动重试机制（最多3次）
- 请求超时控制（30秒）
- 密钥前缀验证

## 安装依赖

```bash
go get golang.org/x/time/rate
```

## 配置

在运行之前，需要设置环境变量：

```bash
export KEY_PREFIX="你的密钥前缀"
```

## 运行

```bash
go run main.go
```

服务器将在 9888 端口启动。

## 使用方法

代理请求格式：
```
http://localhost:9888/proxy/{KEY_PREFIX}/{目标URL}
```

示例：
```
http://localhost:9888/proxy/dsadsafasf/example.com/api/data
```

## 限制说明

- 单个 IP 限流：每秒最多 10 个请求，突发上限 20 个
- 全局限流：每秒最多 100 个请求，突发上限 200 个
- 请求超时：30 秒
- 重试次数：最多 3 次

## 注意事项

- 生产环境使用时建议开启 TLS 证书验证
- 请妥善保管并定期更换密钥前缀
- 建议根据实际需求调整限流参数
