package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 配置常量
const (
	maxRetries     = 3                 // 最大重试次数
	timeout        = 60 * time.Second  // 请求超时时间
	ipLogFile      = "ip_access.log"   // IP访问日志文件
	bufferSize     = 8 * 1024          // 8KB 的缓冲区大小
	serverPort     = ":9888"           // 服务器监听端口
	rateLimit      = 100               // 全局每秒请求限制
	burstLimit     = 200               // 全局突发请求限制
	perIPLimit     = 10                // 每个IP每秒请求限制
	perIPBurst     = 20                // 每个IP突发请求限制
	maxContentSize = 100 * 1024 * 1024 // 100MB 最大内容大小限制
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

// 流式内容类型
var streamingContentTypes = map[string]bool{
	"text/event-stream":        true,
	"application/x-ndjson":     true,
	"text/plain":               true, // 某些流式API使用text/plain
	"application/json":         true, // 某些流式JSON API
	"application/octet-stream": true,
}

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
	logUnauthorizedAccess(r)
	http.Error(w, "404 路径错误", http.StatusNotFound)
}

// 记录未授权访问
func logUnauthorizedAccess(r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("未授权访问 - IP: %s, 路径: %s, 方法: %s, User-Agent: %s",
		clientIP, r.URL.Path, r.Method, r.Header.Get("User-Agent"))
}

// 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 优先检查 X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// 使用 RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// 初始化函数
func init() {
	initLogger()
}

// 主函数
func main() {
	setupKeyPrefix()
	setupRoutes()
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
	enableRateLimit = true
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
	http.Handle("/", &customNotFoundHandler{})
}

// 启动服务器
func startServer() {
	log.Printf("代理服务器启动在 %s 端口", serverPort)
	server := &http.Server{
		Addr:         serverPort,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second, // 为流式传输设置更长的写超时
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
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

// 改进的流式传输判断
func isStreamingResponse(resp *http.Response) bool {
	// 1. 检查 Transfer-Encoding: chunked
	if resp.Header.Get("Transfer-Encoding") == "chunked" {
		return true
	}

	// 2. 检查 Content-Type 是否为流式类型
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	for streamType := range streamingContentTypes {
		if strings.Contains(contentType, streamType) {
			return true
		}
	}

	// 3. 检查 Content-Length
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		// 没有 Content-Length 且不是 chunked，可能是流式
		return true
	}

	// 4. 检查 Cache-Control
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		if strings.Contains(strings.ToLower(cacheControl), "no-cache") ||
			strings.Contains(strings.ToLower(cacheControl), "no-store") {
			return true
		}
	}

	// 5. 检查特定的流式响应头
	if resp.Header.Get("X-Accel-Buffering") == "no" ||
		resp.Header.Get("X-Stream") == "true" {
		return true
	}

	return false
}

// 日志记录IP访问信息
func logIPAccess(r *http.Request) {
	logMutex.Lock()
	defer logMutex.Unlock()
	clientIP := getClientIP(r)
	ipLogger.Printf("IP: %s, 方法: %s, 路径: %s, User-Agent: %s",
		clientIP, r.Method, r.URL.Path, r.Header.Get("User-Agent"))
}

// 创建HTTP客户端
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   30,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    false, // 启用压缩以提高效率
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
	// 添加请求上下文和超时控制
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	logIPAccess(r)
	log.Printf("收到请求: %s %s", r.Method, r.URL.Path)

	fullPath := strings.TrimPrefix(r.URL.Path, "/proxy/")
	if !validateRequestPath(fullPath, w) {
		return
	}

	if !handleRateLimiting(w, r) {
		return
	}

	targetURL := buildTargetURL(fullPath, r)
	log.Printf("目标URL: %s", targetURL)

	if !validateURLSafety(targetURL) {
		log.Printf("不安全的URL: %s", targetURL)
		http.Error(w, "不允许访问的URL", http.StatusForbidden)
		return
	}

	executeProxyRequest(ctx, w, r, targetURL)
}

// 限流处理
func handleRateLimiting(w http.ResponseWriter, r *http.Request) bool {
	if !enableRateLimit {
		return true
	}

	clientIP := getClientIP(r)
	if !getClientLimiter(clientIP).Allow() {
		log.Printf("IP %s 请求过于频繁", clientIP)
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

// 复制HTTP头（排除不应该代理的头）
func copyHeaders(dst, src http.Header) {
	hopByHopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	for header, values := range src {
		if !hopByHopHeaders[header] {
			for _, value := range values {
				dst.Add(header, value)
			}
		}
	}
}

// 执行代理请求
func executeProxyRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, targetURL string) {
	client := createHTTPClient()

	var resp *http.Response
	var err error

	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			http.Error(w, "请求超时", http.StatusRequestTimeout)
			return
		default:
		}

		// 创建新的请求
		proxyReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
		if err != nil {
			log.Printf("第 %d 次创建请求失败: %v", i+1, err)
			continue
		}

		copyHeaders(proxyReq.Header, r.Header)

		// 设置代理相关头
		proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
		proxyReq.Header.Set("X-Forwarded-Proto", "https")

		log.Printf("第 %d 次尝试请求", i+1)

		resp, err = client.Do(proxyReq)
		if err == nil {
			break
		}

		log.Printf("第 %d 次请求失败: %v", i+1, err)
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	if err != nil {
		log.Printf("所有重试都失败: %v", err)
		http.Error(w, "代理请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("收到响应: %s", resp.Status)

	// 检查内容大小限制
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			if size > maxContentSize {
				log.Printf("响应内容过大: %d 字节", size)
				http.Error(w, "响应内容过大", http.StatusRequestEntityTooLarge)
				return
			}
		}
	}

	// 检查是否需要流式传输
	isStreaming := isStreamingResponse(resp)
	log.Printf("流式传输: %v", isStreaming)

	// 复制响应header
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// 根据是否为流式传输选择不同的处理方式
	if isStreaming {
		handleStreamingResponse(ctx, w, resp)
	} else {
		handleNormalResponse(w, resp)
	}
}

// 处理流式响应
func handleStreamingResponse(ctx context.Context, w http.ResponseWriter, resp *http.Response) {
	flusher, canFlush := w.(http.Flusher)
	if !canFlush {
		log.Println("响应写入器不支持流式传输，降级为普通传输")
		handleNormalResponse(w, resp)
		return
	}

	// 使用 bufio.Reader 进行更高效的读取
	reader := bufio.NewReader(resp.Body)
	buffer := make([]byte, bufferSize)

	for {
		select {
		case <-ctx.Done():
			log.Println("流式传输被中断")
			return
		default:
		}

		n, err := reader.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				log.Printf("写入响应数据失败: %v", writeErr)
				return
			}
			flusher.Flush()
		}

		if err != nil {
			if err == io.EOF {
				log.Println("流式传输完成")
			} else {
				log.Printf("读取响应数据失败: %v", err)
			}
			return
		}
	}
}

// 处理普通响应
func handleNormalResponse(w http.ResponseWriter, resp *http.Response) {
	// 使用 LimitReader 防止内存耗尽
	limitedReader := io.LimitReader(resp.Body, maxContentSize)

	bytesCopied, err := io.Copy(w, limitedReader)
	if err != nil {
		log.Printf("复制响应内容失败: %v", err)
	} else {
		log.Printf("成功复制响应内容: %d 字节", bytesCopied)
	}
}

// 验证 URL 的函数
func isValidURL(targetURL string) bool {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	if !isValidDomain(parsedURL.Hostname()) {
		return false
	}

	if isBlockedDomain(parsedURL.Hostname()) {
		return false
	}

	return true
}

// 域名格式验证（改进版）
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// 长度检查
	if len(domain) > 253 {
		return false
	}

	// 域名正则验证（更严格）
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	// IPv4 地址验证
	ipv4Regex := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)

	// IPv6 地址验证（简化版）
	ipv6Regex := regexp.MustCompile(`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)

	return domainRegex.MatchString(domain) || ipv4Regex.MatchString(domain) || ipv6Regex.MatchString(domain)
}

// 屏蔽域名检查（改进版）
func isBlockedDomain(domain string) bool {
	// 屏蔽的域名列表
	blockedDomains := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"::1",
		"[::1]",
	}

	// 私有网段正则表达式
	privateNetworkRegexes := []*regexp.Regexp{
		regexp.MustCompile(`^10\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
		regexp.MustCompile(`^172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
		regexp.MustCompile(`^192\.168\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
		regexp.MustCompile(`^169\.254\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`), // 链路本地地址
	}

	// 检查域名黑名单
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

// URL 安全检查扩展函数（改进版）
func validateURLSafety(targetURL string) bool {
	if !isValidURL(targetURL) {
		return false
	}

	// 长度限制
	if len(targetURL) > 4096 {
		return false
	}

	// 解析URL进行更详细的检查
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// 检查端口范围
	if parsedURL.Port() != "" {
		port, err := strconv.Atoi(parsedURL.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		// 阻止访问某些敏感端口
		sensitiveports := []int{22, 23, 25, 53, 135, 139, 445, 993, 995, 1433, 3306, 3389, 5432, 6379}
		for _, sp := range sensitiveports {
			if port == sp {
				return false
			}
		}
	}

	// 特殊字符和路径检查
	unsafePatterns := []string{
		"../", "..%2f", "..%5c", "%00", "<script", "javascript:", "vbscript:", "data:", "file:",
		"@", // 防止用户信息注入
	}

	lowerURL := strings.ToLower(targetURL)
	for _, pattern := range unsafePatterns {
		if strings.Contains(lowerURL, pattern) {
			return false
		}
	}

	return true
}
