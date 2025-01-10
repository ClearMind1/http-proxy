package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 配置常量
const (
	maxRetries = 2                // 最大重试次数
	timeout    = 30 * time.Second // 请求超时时间
	ipLogFile  = "ip_access.log"  // IP访问日志文件
	bufferSize = 4 * 1024         // 1KB 的缓冲区大小
	serverPort = ":9888"          // 服务器监听端口
	rateLimit  = 100              // 全局每秒请求限制
	burstLimit = 200              // 全局突发请求限制
	perIPLimit = 10               // 每个IP每秒请求限制
	perIPBurst = 20               // 每个IP突发请求限制
)

// 全局变量和配置
var (
	keyPrefix       string                                               // 密钥前缀
	enableRateLimit bool                                                 // 是否启用限流
	limiter         = rate.NewLimiter(rate.Limit(rateLimit), burstLimit) // 全局限流器
	clients         sync.Map                                             // 存储每个IP的限流器
	ipLogger        *log.Logger                                          // IP访问日志记录器
	logMutex        sync.Mutex                                           // 日志写入互斥锁
)

// 初始化日志记录器
func initLogger() {
	logFile, err := os.OpenFile(ipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("无法创建IP日志文件:", err)
	}
	ipLogger = log.New(logFile, "", log.LstdFlags)
}

// 自定义的 NotFoundHandler
type customNotFoundHandler struct{}

// 实现 ServeHTTP 接口
func (h *customNotFoundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 记录未授权访问的尝试
	logUnauthorizedAccess(r)
	// 返回 404 页面
	http.Error(w, "404 路径错误", http.StatusNotFound)
}

// 可选：添加更详细的日志记录
func logUnauthorizedAccess(r *http.Request) {
	log.Printf("未授权访问 - IP: %s, 路径: %s, 方法: %s, User-Agent: %s",
		r.RemoteAddr,
		r.URL.Path,
		r.Method,
		r.Header.Get("User-Agent"),
	)
}

// 初始化函数
func init() {
	initLogger()
}

// 主函数
func main() {
	// 配置密钥前缀
	setupKeyPrefix()

	// 配置路由
	setupRoutes()

	// 启动服务器
	startServer()
}

// 设置密钥前缀
func setupKeyPrefix() {
	keyPrefix = strings.Trim(os.Getenv("KEY_PREFIX"), "\"")
	log.Println("当前密钥前缀:", keyPrefix)

	if keyPrefix == "" {
		log.Fatal("环境变量 KEY_PREFIX 未设置")
	}
	// 处理限流开关环境变量
	enableRateLimit = true // 默认启用限流
	if rateLimitStr := os.Getenv("ENABLE_RATE_LIMIT"); rateLimitStr != "" {
		if rateLimitStr == "false" || rateLimitStr == "0" {
			enableRateLimit = false
			log.Println("限流功能已禁用")
		}
	}
}

// 配置路由
func setupRoutes() {
	http.HandleFunc("/proxy/", proxyHandler)
	// 使用自定义处理器替换默认的 NotFoundHandler
	http.Handle("/", &customNotFoundHandler{})
}

// 启动服务器
func startServer() {
	log.Printf("代理服务器启动在 %s 端口", serverPort)
	if err := http.ListenAndServe(serverPort, nil); err != nil {
		log.Fatal(err)
	}
}

// 获取客户端IP的限流器
func getClientLimiter(ip string) *rate.Limiter {
	if l, exists := clients.Load(ip); exists {
		return l.(*rate.Limiter)
	}

	l := rate.NewLimiter(rate.Limit(perIPLimit), perIPBurst)
	clients.Store(ip, l)
	return l
}

// 根据响应判断是否是流式传输
func isStreamingRequest(resp *http.Response) bool {
	// 检查是否有 "Transfer-Encoding: chunked"
	if resp.Header.Get("Transfer-Encoding") == "chunked" {
		return true
	}

	// 检查是否有 "Content-Length"，如果没有，则可能是流式传输
	if resp.Header.Get("Content-Length") == "" {
		return true
	}

	return false
}

// 日志记录IP访问信息
func logIPAccess(r *http.Request) {
	logMutex.Lock()
	defer logMutex.Unlock()
	ipLogger.Printf("IP: %s, 方法: %s, 路径: %s, User-Agent: %s",
		r.RemoteAddr, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
}

// 创建HTTP客户端
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 注意：生产环境中应验证证书
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// 构建目标URL
func buildTargetURL(path string, r *http.Request) string {
	targetURL := strings.TrimPrefix(path, keyPrefix+"/")
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	return targetURL
}

// 处理代理请求
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 记录IP访问信息
	logIPAccess(r)

	log.Printf("收到请求: %s %s", r.Method, r.URL.Path)

	// 提取完整路径
	fullPath := strings.TrimPrefix(r.URL.Path, "/proxy/")
	// 判断是否含有Prefix
	if !validateRequestPath(fullPath, w) {
		return
	}

	// 限流处理
	if !handleRateLimiting(w, r) {
		return
	}

	// 去掉 Prefix 构建目标URL
	targetURL := buildTargetURL(fullPath, r)
	log.Printf("目标URL: %s", targetURL)

	// 判断是否为有效链接
	// 目标URL安全性检查
	if !validateURLSafety(targetURL) {
		log.Printf("不安全的URL: %s", targetURL)
		http.Error(w, "不允许访问的URL", http.StatusForbidden)
		return
	}

	// 执行代理请求
	executeProxyRequest(w, r, targetURL)
}

// 限流处理
func handleRateLimiting(w http.ResponseWriter, r *http.Request) bool {
	// 不限流则返回true
	if !enableRateLimit {
		return true
	}
	ip := r.RemoteAddr
	if !getClientLimiter(ip).Allow() {
		log.Printf("IP %s 请求过于频繁", ip)
		http.Error(w, "请求过于频繁", http.StatusTooManyRequests)
		return false
	}

	if !limiter.Allow() {
		log.Println("服务器负载过高，请稍后重试")
		http.Error(w, "服务器繁忙，请稍后重试", http.StatusTooManyRequests)
		return false
	}
	return true
}

// 验证请求路径
func validateRequestPath(path string, w http.ResponseWriter) bool {
	if !strings.HasPrefix(path, keyPrefix+"/") {
		log.Printf("无效的请求: 缺少或错误的密钥前缀 - %s", path)
		http.Error(w, "无效的请求!", http.StatusForbidden)
		return false
	}
	return true
}

// 复制HTTP头
func copyHeaders(dst, src http.Header) {
	for header, values := range src {
		for _, value := range values {
			dst.Add(header, value)
		}
	}
}

// 执行代理请求
func executeProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	// 创建带超时的HTTP客户端
	client := createHTTPClient()

	// 实现重试机制
	var resp *http.Response
	var err error
	for i := 0; i < maxRetries; i++ {
		// 创建新的请求
		proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
		if err != nil {
			log.Printf("第 %d 次创建请求失败: %v", i+1, err)
			continue
		}

		// 复制原始请求的header
		copyHeaders(proxyReq.Header, r.Header)
		log.Printf("第 %d 次尝试请求", i+1)

		// 发送请求
		resp, err = client.Do(proxyReq)
		if err == nil {
			break
		}

		log.Printf("第 %d 次请求失败: %v", i+1, err)
		if i < maxRetries-1 {
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	// 处理最终的错误
	if err != nil {
		log.Printf("所有重试都失败: %v", err)
		http.Error(w, "代理请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("收到响应: %s", resp.Status)

	// 检查是否需要流式传输
	isStreaming := isStreamingRequest(resp)

	// 复制响应header
	copyHeaders(w.Header(), resp.Header)

	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)

	// 根据是否为流式传输选择不同的处理方式
	if isStreaming {
		log.Printf("流式响应")
		handleStreamingResponse(w, resp)
	} else {
		log.Printf("非流式响应")
		handleNormalResponse(w, resp)
	}
}

// 处理流式响应
func handleStreamingResponse(w http.ResponseWriter, resp *http.Response) {
	if flusher, ok := w.(http.Flusher); ok {
		buffer := make([]byte, bufferSize)
		for {
			n, err := resp.Body.Read(buffer)
			if n > 0 {
				_, writeErr := w.Write(buffer[:n])
				if writeErr != nil {
					log.Printf("写入响应数据失败: %v", writeErr)
					return
				}
				flusher.Flush()
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("读取响应数据失败: %v", err)
				}
				return
			}
		}
	} else {
		log.Println("当前响应写入器不支持流式传输")
		// 降级为普通传输
		_, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("复制响应内容失败: %v", err)
		}
	}
}

// 处理普通响应
func handleNormalResponse(w http.ResponseWriter, resp *http.Response) {
	bytesCopied, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("复制响应内容失败: %v", err)
	} else {
		log.Printf("成功复制响应内容: %d 字节", bytesCopied)
	}
}

// 验证 URL 的函数
func isValidURL(targetURL string) bool {
	// 步骤1：基本 URL 解析验证
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// 步骤2：检查协议
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	// 步骤3：域名验证
	if !isValidDomain(parsedURL.Hostname()) {
		return false
	}

	// 步骤4：禁止某些特定域名或IP
	if isBlockedDomain(parsedURL.Hostname()) {
		return false
	}

	return true
}

// 域名格式验证
func isValidDomain(domain string) bool {
	// 域名正则验证
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$`)

	// IP 地址验证
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

	return domainRegex.MatchString(domain) || ipRegex.MatchString(domain)
}

// 屏蔽域名检查
func isBlockedDomain(domain string) bool {
	// 屏蔽的域名列表
	blockedDomains := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"::1",
		// 添加其他需要屏蔽的域名
	}

	// 私有网段屏蔽
	privateNetworkRegexes := []*regexp.Regexp{
		regexp.MustCompile(`^10\.\d+\.\d+\.\d+$`),                  // 10.0.0.0/8
		regexp.MustCompile(`^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$`), // 172.16.0.0/12
		regexp.MustCompile(`^192\.168\.\d+\.\d+$`),                 // 192.168.0.0/16
	}

	// 检查是否在屏蔽列表中
	for _, blockedDomain := range blockedDomains {
		if strings.EqualFold(domain, blockedDomain) {
			return true
		}
	}

	// 检查私有网段
	for _, regex := range privateNetworkRegexes {
		if regex.MatchString(domain) {
			return true
		}
	}

	return false
}

// URL 安全检查扩展函数
func validateURLSafety(targetURL string) bool {
	// 步骤1：基本 URL 有效性检查
	if !isValidURL(targetURL) {
		return false
	}

	// 步骤2：长度限制
	if len(targetURL) > 2048 {
		return false
	}

	// 步骤3：特殊字符和路径检查
	unsafePatterns := []string{
		"../",         // 目录遍历
		"..%2f",       // 编码的目录遍历
		"%00",         // 空字节注入
		"<script",     // 防止 XSS
		"javascript:", // 防止脚本注入
	}

	for _, pattern := range unsafePatterns {
		if strings.Contains(strings.ToLower(targetURL), pattern) {
			return false
		}
	}

	return true
}
