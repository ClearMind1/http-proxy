package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
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
	bufferSize = 32 * 1024        // 32KB 的缓冲区大小
	serverPort = ":9888"          // 服务器监听端口
	rateLimit  = 100              // 全局每秒请求限制
	burstLimit = 200              // 全局突发请求限制
	perIPLimit = 10               // 每个IP每秒请求限制
	perIPBurst = 20               // 每个IP突发请求限制
)

// 全局变量和配置
var (
	keyPrefix string                                               // 密钥前缀
	limiter   = rate.NewLimiter(rate.Limit(rateLimit), burstLimit) // 全局限流器
	clients   sync.Map                                             // 存储每个IP的限流器
	ipLogger  *log.Logger                                          // IP访问日志记录器
	logMutex  sync.Mutex                                           // 日志写入互斥锁
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

// 检查是否为流式请求
func isStreamingRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Accept"), "text/event-stream") ||
		strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "stream")
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

	// 严格验证路径是否以 keyPrefix 开头
	if !strings.HasPrefix(fullPath, keyPrefix+"/") {
		log.Printf("无效的请求路径: %s", r.URL.Path)

		// 返回 404
		http.Error(w, "404 页面未找到", http.StatusNotFound)
		return
	}

	// 限流处理
	if !handleRateLimiting(w, r) {
		return
	}

	// 验证和处理请求路径
	path := strings.TrimPrefix(fullPath, keyPrefix+"/")
	if !validateRequestPath(path, w) {
		return
	}

	// 构建目标URL
	targetURL := buildTargetURL(path, r)
	log.Printf("目标URL: %s", targetURL)

	// 执行代理请求
	executeProxyRequest(w, r, targetURL)
}

// 限流处理
func handleRateLimiting(w http.ResponseWriter, r *http.Request) bool {
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
	isStreaming := isStreamingRequest(r)

	// 复制响应header
	copyHeaders(w.Header(), resp.Header)

	// 如果是流式传输，设置相应的header
	if isStreaming {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}

	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)

	// 根据是否为流式传输选择不同的处理方式
	if isStreaming {
		handleStreamingResponse(w, resp)
	} else {
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
