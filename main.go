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

var keyPrefix string

const (
	maxRetries = 2                // 最大重试次数
	timeout    = 30 * time.Second // 请求超时时间
	ipLogFile  = "ip_access.log"  // IP访问日志文件
	bufferSize = 32 * 1024        // 32KB 的缓冲区大小
)

// 全局限流配置
var (
	limiter  = rate.NewLimiter(rate.Limit(100), 200) // 每秒100个请求，突发200个
	clients  sync.Map                                // 存储每个IP的限流器
	ipLogger *log.Logger                             // IP访问日志记录器
	logMutex sync.Mutex                              // 日志写入互斥锁
)

func init() {
	// 初始化IP日志记录器
	logFile, err := os.OpenFile(ipLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("无法创建IP日志文件:", err)
	}
	ipLogger = log.New(logFile, "", log.LstdFlags)
}

func main() {
	// 从环境变量获取密钥前缀，并去除可能存在的引号
	keyPrefix = strings.Trim(os.Getenv("KEY_PREFIX"), "\"")
	log.Println("当前密钥前缀:", keyPrefix)
	if keyPrefix == "" {
		log.Fatal("环境变量 KEY_PREFIX 未设置")
	}

	// 设置路由处理
	http.HandleFunc("/proxy/", proxyHandler)

	// 启动服务器
	log.Println("代理服务器启动在 :9888 端口")
	if err := http.ListenAndServe(":9888", nil); err != nil {
		log.Fatal(err)
	}
}

// 获取客户端IP的限流器
func getClientLimiter(ip string) *rate.Limiter {
	if l, exists := clients.Load(ip); exists {
		return l.(*rate.Limiter)
	}

	l := rate.NewLimiter(rate.Limit(10), 20) // 每个IP每秒10个请求，突发20个
	clients.Store(ip, l)
	return l
}

// 检查是否为流式请求的辅助函数
func isStreamingRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Accept"), "text/event-stream") ||
		strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "stream")
}

// 代理处理函数
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// 记录IP访问信息
	logMutex.Lock()
	ipLogger.Printf("IP: %s, 方法: %s, 路径: %s, User-Agent: %s",
		r.RemoteAddr,
		r.Method,
		r.URL.Path,
		r.Header.Get("User-Agent"))
	logMutex.Unlock()

	log.Printf("收到请求: %s %s", r.Method, r.URL.Path)

	// 实现IP限流
	ip := r.RemoteAddr
	if !getClientLimiter(ip).Allow() {
		log.Printf("IP %s 请求过于频繁", ip)
		http.Error(w, "请求过于频繁", http.StatusTooManyRequests)
		return
	}

	// 全局限流
	if !limiter.Allow() {
		log.Println("服务器负载过高，请稍后重试")
		http.Error(w, "服务器繁忙，请稍后重试", http.StatusTooManyRequests)
		return
	}

	// 从URL中提取目标地址
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")

	// 检查前缀密钥
	if !strings.HasPrefix(path, keyPrefix+"/") {
		log.Printf("无效的请求: 缺少或错误的密钥前缀 - %s", path)
		http.Error(w, "无效的请求!", http.StatusForbidden)
		return
	}

	// 去掉密钥前缀并保留查询参数
	targetURL := strings.TrimPrefix(path, keyPrefix+"/")
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}
	log.Printf("目标URL: %s", targetURL)

	// 如果URL不是以http或https开头，添加https://
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
		log.Printf("添加https前缀: %s", targetURL)
	}

	// 创建带超时的HTTP客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 注意：生产环境中应验证证书
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

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
		// 流式传输处理
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
	} else {
		// 普通传输处理
		bytesCopied, err := io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("复制响应内容失败: %v", err)
		} else {
			log.Printf("成功复制响应内容: %d 字节", bytesCopied)
		}
	}
}

// 辅助函数：复制 HTTP 头
func copyHeaders(dst, src http.Header) {
	for header, values := range src {
		for _, value := range values {
			dst.Add(header, value)
		}
	}
}
