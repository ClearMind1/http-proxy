
# Go HTTP 代理服务器

一个基于 Go 语言开发的高性能 简单HTTP 代理服务器，支持请求转发、限流控制和安全验证。

## 主要特性

- 🚀 高性能请求转发
- 🔒 请求安全验证
- 🌊 流量控制
  - 全局限流
  - 基于 IP 的限流
- 🔄 自动重试机制
- 📝 详细的访问日志
- 🛡️ URL 安全检查
- 🔌 支持流式响应，可作为AI API的流式代理

## 快速开始

### Docker 部署

```bash
# 构建镜像
docker build -t proxy-server .

# 运行容器
docker run -d \
  -p 9888:9888 \
  -e KEY_PREFIX="your_key_prefix" \
  -e ENABLE_RATE_LIMIT=true \
  proxy-server
```

### 环境变量配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| KEY_PREFIX | 请求路径前缀，用于验证 | 必填 |
| ENABLE_RATE_LIMIT | 是否启用限流 | true |

### 系统配置

```go
const (
    maxRetries = 2                // 最大重试次数
    timeout    = 30 * time.Second // 请求超时时间
    serverPort = ":9888"          // 服务器端口
    rateLimit  = 100              // 全局每秒请求限制
    perIPLimit = 10               // 每IP每秒请求限制
)
```

## API 使用说明

### 请求格式

```
http://localhost:9888/proxy/{KEY_PREFIX}/{target_url}
```

示例：
```bash
# 如果 KEY_PREFIX = "abc123"
curl "http://localhost:9888/proxy/abc123/api.example.com/data"
```

## 安全特性

- URL 安全性验证
- 私有网络访问限制
- 特殊字符过滤
- 域名黑名单
- 请求长度限制

## 监控和日志

- 访问日志记录在 `ip_access.log`
- 详细的请求响应日志
- 错误追踪

## 限流说明

- 全局限流：100 请求/秒
- 单 IP 限流：10 请求/秒
- 突发流量处理：
  - 全局突发上限：200 请求
  - 单 IP 突发上限：20 请求

## 注意事项

1. 生产环境部署时建议修改默认的 `KEY_PREFIX`
2. 建议在反向代理后面运行
3. 需要定期检查和清理日志文件
4. 建议配置 SSL/TLS 证书

## 技术栈

- Go 1.23+
