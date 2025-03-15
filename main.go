package main

import (
	"encoding/json"
	"html"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"
)

// Import for embedding files

//go:embed VERSION
var embeddedVersion string

//go:embed favicon.ico
var faviconData []byte

// Configuration defaults
var (
	DEFAULT_PORT        = "3000"
	MAX_BODY_SIZE int64 = 1024 * 1024 // 1MB max body size
	RATE_LIMIT          = 100         // requests per minute
	RATE_WINDOW         = time.Minute // time window for rate limiting
	HTML_MODE           = false       // Default to original behavior (JSON)
)

type RequestInfo struct {
	URL                string              `json:"url"`
	Method             string              `json:"method"`
	QueryParams        map[string][]string `json:"query_params"`
	Headers            map[string][]string `json:"headers"`
	Cookies            map[string]string   `json:"cookies"`
	Body               string              `json:"body"`
	UserAgent          string              `json:"user_agent"`
	RemoteAddr         string              `json:"remote_addr"`
	Host               string              `json:"host"`
	Referer            string              `json:"referer"`
	ContentLength      int64               `json:"content_length"`
	ContentType        string              `json:"content_type"`
	ServerTime         string              `json:"server_time"`
	ServerTimeStampUTC int64               `json:"server_timestamp_utc"`
	OnewayTripTime     int64               `json:"oneway_trip_ms"`
	RoundTripTime      int64               `json:"roundtrip_ms"`
	ServerHostname     string              `json:"server_hostname"`
	ServerLocalIP      string              `json:"server_local_ip"`
	ServerVersion      string              `json:"server_version"`
	BodyTruncated      bool                `json:"body_truncated,omitempty"`
}

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	requests     map[string][]time.Time
	mutex        sync.Mutex
	limit        int
	windowPeriod time.Duration
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:     make(map[string][]time.Time),
		limit:        limit,
		windowPeriod: window,
	}
}

// Allow checks if a request from a given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowPeriod)

	// Clean up old requests
	if requests, found := rl.requests[ip]; found {
		newRequests := []time.Time{}
		for _, t := range requests {
			if t.After(cutoff) {
				newRequests = append(newRequests, t)
			}
		}
		rl.requests[ip] = newRequests
	}

	// Check if request count is under the limit
	requestCount := len(rl.requests[ip])
	if requestCount >= rl.limit {
		return false
	}

	// Add the current request
	rl.requests[ip] = append(rl.requests[ip], now)
	return true
}

// GetRemainingRequests returns the number of remaining requests allowed for an IP
func (rl *RateLimiter) GetRemainingRequests(ip string) int {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	cutoff := time.Now().Add(-rl.windowPeriod)

	// Count valid requests in the window
	count := 0
	if requests, found := rl.requests[ip]; found {
		for _, t := range requests {
			if t.After(cutoff) {
				count++
			}
		}
	}

	return rl.limit - count
}

// GetLocalIP returns the first non-loopback IPv4 address
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Error getting network interfaces: %v", err)
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}

// GetClientIP extracts the client's real IP address from headers or RemoteAddr
func GetClientIP(r *http.Request) string {
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			clientIP = forwardedFor
		} else {
			clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	}
	return clientIP
}

// EnableCORS adds Cross-Origin Resource Sharing headers to responses
func EnableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Date")
}

// Check if the request prefers JSON based on Accept header
func prefersJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")

	// If HTML_MODE is enabled, we only return JSON if it's explicitly requested
	if HTML_MODE {
		return strings.Contains(accept, "application/json")
	}

	// Default behavior (original): return JSON unless /html endpoint is used
	return true
}

// loadConfig loads configuration from environment variables
func loadConfig() {
	// Initialize version from embedded file
	embeddedVersion = strings.TrimSpace(embeddedVersion)
	if embeddedVersion == "" {
		embeddedVersion = "unknown"
	}

	// Port configuration
	if envPort := os.Getenv("PORT"); envPort != "" {
		DEFAULT_PORT = envPort
	}

	// Body size limit
	if envBodySize := os.Getenv("MAX_BODY_SIZE"); envBodySize != "" {
		if size, err := strconv.ParseInt(envBodySize, 10, 64); err == nil && size > 0 {
			MAX_BODY_SIZE = size
			log.Printf("Setting MAX_BODY_SIZE to %d bytes from environment", MAX_BODY_SIZE)
		}
	}

	// Rate limit configuration
	if envRateLimit := os.Getenv("RATE_LIMIT"); envRateLimit != "" {
		if limit, err := strconv.Atoi(envRateLimit); err == nil && limit > 0 {
			RATE_LIMIT = limit
			log.Printf("Setting RATE_LIMIT to %d requests from environment", RATE_LIMIT)
		}
	}

	// Rate window configuration
	if envRateWindow := os.Getenv("RATE_WINDOW"); envRateWindow != "" {
		if seconds, err := strconv.Atoi(envRateWindow); err == nil && seconds > 0 {
			RATE_WINDOW = time.Duration(seconds) * time.Second
			log.Printf("Setting RATE_WINDOW to %v from environment", RATE_WINDOW)
		}
	}

	// HTML_MODE configuration
	if htmlMode := os.Getenv("HTML_MODE"); htmlMode != "" {
		// Case insensitive check for true/false values
		htmlModeLower := strings.ToLower(htmlMode)
		if htmlModeLower == "true" || htmlModeLower == "1" || htmlModeLower == "yes" || htmlModeLower == "y" || htmlModeLower == "on" {
			HTML_MODE = true
			log.Printf("HTML_MODE is enabled, defaulting to HTML responses except when JSON is requested")
		} else if htmlModeLower == "false" || htmlModeLower == "0" || htmlModeLower == "no" || htmlModeLower == "n" || htmlModeLower == "off" {
			HTML_MODE = false
			log.Printf("HTML_MODE is explicitly disabled, defaulting to JSON responses")
		} else {
			// If set to something unexpected, treat existence as true
			HTML_MODE = true
			log.Printf("HTML_MODE has unrecognized value '%s', treating as enabled", htmlMode)
		}
	}
}

func main() {
	// Load configuration from environment
	loadConfig()

	// Set up the HTTP server
	port := DEFAULT_PORT
	bindAddress := ":" + port

	// Create a new rate limiter with configured values
	rateLimiter := NewRateLimiter(RATE_LIMIT, RATE_WINDOW)

	// Set up HTTP handlers
	// Handler for favicon.ico
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 1 day
		w.Write(faviconData)

		// Log the favicon request
		clientIP := GetClientIP(r)
		log.Printf("Served favicon.ico to %s", clientIP)
	})

	http.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			EnableCORS(w)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Apply rate limiting based on client IP
		clientIP := GetClientIP(r)
		if !rateLimiter.Allow(clientIP) {
			remaining := rateLimiter.GetRemainingRequests(clientIP)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(RATE_LIMIT))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(RATE_WINDOW).Unix(), 10))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for %s", clientIP)
			return
		}

		// Process the request and return HTML
		requestInfoHandlerHTML(w, r, clientIP, rateLimiter)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			EnableCORS(w)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Apply rate limiting based on client IP
		clientIP := GetClientIP(r)
		if !rateLimiter.Allow(clientIP) {
			remaining := rateLimiter.GetRemainingRequests(clientIP)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(RATE_LIMIT))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(RATE_WINDOW).Unix(), 10))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			log.Printf("Rate limit exceeded for %s", clientIP)
			return
		}

		// Process the request based on content negotiation
		if prefersJSON(r) {
			// Client prefers JSON or we're in default mode
			requestInfoHandler(w, r, clientIP, rateLimiter)
		} else {
			// Client prefers HTML or PREFER_HTML is enabled
			requestInfoHandlerHTML(w, r, clientIP, rateLimiter)
		}
	})

	log.Printf("Server version %s started on %s\n", embeddedVersion, bindAddress)
	log.Fatal(http.ListenAndServe(bindAddress, nil))
}

// HTML template for the HTML view
var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Information</title>
    <style>
        body {
            font-family: sans-serif;
            color: #000;
            background-color: #fff;
            margin: 0;
            padding: 0;
            font-size: 14px;
            line-height: 1.4;
        }
        a {
            color: #3677a9;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        h1 {
            color: #000;
            font-size: 24px;
            margin: 30px 15px 15px 15px;
        }
        .section {
            margin: 0;
            padding: 10px;
        }
        .section h2 {
            font-size: 16px;
            background-color: #9999cc;
            padding: 5px 10px;
            color: #000;
            margin: 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            border: 0;
            background-color: #D0D0D0;
        }
        tr {
            background-color: #f8f8f8;
        }
        tr:nth-child(odd) {
            background-color: #fff;
        }
        th {
            text-align: left;
            padding: 4px;
            font-weight: bold;
            border-bottom: 1px solid #ccc;
            background-color: #eee;
        }
        td {
            padding: 4px;
            border: 0;
            vertical-align: top;
        }
        td.e {
            width: 220px;
            background-color: #e8e8e8;
            font-weight: bold;
            color: #000;
        }
        td.v {
            word-break: break-all;
            color: #000;
        }
        .center {
            text-align: center;
        }
        .right {
            text-align: right;
            padding-right: 10px;
        }
        pre {
            border: 1px solid #ccc;
            padding: 10px;
            background-color: #f8f8f8;
            overflow-x: auto;
            font-family: monospace;
            font-size: 13px;
            line-height: 1.2;
        }
        .body-container {
            margin: 10px;
        }
        footer {
            margin: 15px;
            text-align: right;
            color: #333;
            font-size: 12px;
        }
        .server-bar {
            position: sticky;
            top: 0;
            background-color: white;
            padding: 10px;
            border-bottom: 1px solid #ccc;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .server-info {
            font-size: 12px;
        }
        .alt-view {
            text-align: right;
            margin: 10px;
        }
        .highlight {
            background-color: #ffffd0;
        }
    </style>
</head>
<body>
    <div class="server-bar">
        <h1>Request Information</h1>
        <div class="server-info">
            Server Version: {{.ServerVersion}} | 
            IP: {{.ServerLocalIP}} | 
            Host: {{.ServerHostname}}
        </div>
    </div>
    
    <div class="section">
        <h2>Basic Request Information</h2>
        <table>
            <tr>
                <td class="e">Method</td>
                <td class="v">{{.Method}}</td>
            </tr>
            <tr>
                <td class="e">URL</td>
                <td class="v">{{.URL}}</td>
            </tr>
            <tr>
                <td class="e">Remote Address</td>
                <td class="v">{{.RemoteAddr}}</td>
            </tr>
            <tr>
                <td class="e">Host</td>
                <td class="v">{{.Host}}</td>
            </tr>
            <tr>
                <td class="e">User Agent</td>
                <td class="v">{{.UserAgent}}</td>
            </tr>
            <tr>
                <td class="e">Content Type</td>
                <td class="v">{{.ContentType}}</td>
            </tr>
            <tr>
                <td class="e">Content Length</td>
                <td class="v">{{.ContentLength}} bytes</td>
            </tr>
            <tr>
                <td class="e">Referer</td>
                <td class="v">{{if .Referer}}{{.Referer}}{{else}}None{{end}}</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Server Information</h2>
        <table>
            <tr>
                <td class="e">Server Time</td>
                <td class="v">{{.ServerTime}}</td>
            </tr>
            <tr>
                <td class="e">Server Timestamp (UTC)</td>
                <td class="v">{{.ServerTimeStampUTC}}</td>
            </tr>
            <tr>
                <td class="e">Server Hostname</td>
                <td class="v">{{.ServerHostname}}</td>
            </tr>
            <tr>
                <td class="e">Server Local IP</td>
                <td class="v">{{.ServerLocalIP}}</td>
            </tr>
            <tr>
                <td class="e">Server Version</td>
                <td class="v">{{.ServerVersion}}</td>
            </tr>
            <tr>
                <td class="e">One-way Trip Time</td>
                <td class="v">{{if gt .OnewayTripTime 0}}{{.OnewayTripTime}} ms{{else}}Not available{{end}}</td>
            </tr>
            <tr>
                <td class="e">Round Trip Time</td>
                <td class="v">{{if gt .RoundTripTime 0}}{{.RoundTripTime}} ms{{else}}Not available{{end}}</td>
            </tr>
        </table>
    </div>
    
    {{if .QueryParams}}
    <div class="section">
        <h2>Query Parameters</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
            {{range $key, $values := .QueryParams}}
                {{range $index, $value := $values}}
                <tr>
                    {{if eq $index 0}}
                    <td class="e" rowspan="{{len $values}}">{{$key}}</td>
                    {{end}}
                    <td class="v">{{$value}}</td>
                </tr>
                {{end}}
            {{end}}
        </table>
    </div>
    {{end}}
    
    {{if .Cookies}}
    <div class="section">
        <h2>Cookies</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
            {{range $name, $value := .Cookies}}
            <tr>
                <td class="e">{{$name}}</td>
                <td class="v">{{$value}}</td>
            </tr>
            {{end}}
        </table>
    </div>
    {{end}}
    
    <div class="section">
        <h2>Headers</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
            {{range $name, $values := .Headers}}
                {{range $index, $value := $values}}
                <tr>
                    {{if eq $index 0}}
                    <td class="e" rowspan="{{len $values}}">{{$name}}</td>
                    {{end}}
                    <td class="v">{{$value}}</td>
                </tr>
                {{end}}
            {{end}}
        </table>
    </div>
    
    {{if .Body}}
    <div class="section">
        <h2>Request Body {{if .BodyTruncated}} (Truncated) {{end}}</h2>
        <div class="body-container">
            <pre>{{.Body}}</pre>
        </div>
    </div>
    {{end}}
    
    <div class="alt-view">
        <a href="/?format=json" target="_blank">View JSON Response</a>
    </div>

    <footer>
        HTTP Request Inspector v{{.ServerVersion}} - Generated at {{.ServerTime}}
    </footer>
</body>
</html>`

// requestInfoHandlerHTML generates an HTML response with request info
func requestInfoHandlerHTML(w http.ResponseWriter, r *http.Request, clientIP string, rateLimiter *RateLimiter) {
	startTime := time.Now()

	// Collect the same request information as the JSON handler
	info := collectRequestInfo(r, clientIP, rateLimiter)

	// Parse the HTML template
	tmpl, err := template.New("request-info").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Error generating HTML response: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Error parsing HTML template: %v", err)
		return
	}

	// Set the content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Add rate limit headers
	remaining := rateLimiter.GetRemainingRequests(clientIP)
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(RATE_LIMIT))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(RATE_WINDOW).Unix(), 10))

	// Add CORS headers
	EnableCORS(w)

	// Execute the template with the request info data
	err = tmpl.Execute(w, info)
	if err != nil {
		log.Printf("Error executing HTML template: %v", err)
		return
	}

	// Calculate and log request processing time
	processingTime := time.Since(startTime)
	log.Printf("Processed HTML request from %s %s %s in %v (remaining: %d/%d)",
		clientIP, r.Method, r.URL.String(), processingTime, remaining, RATE_LIMIT)
}

// collectRequestInfo gathers information about the request
func collectRequestInfo(r *http.Request, clientIP string, rateLimiter *RateLimiter) RequestInfo {
	// Collect request information
	info := RequestInfo{
		URL:                r.URL.String(),
		Method:             r.Method,
		QueryParams:        r.URL.Query(),
		Headers:            r.Header,
		Cookies:            make(map[string]string), // Initialize directly
		Body:               "",
		UserAgent:          r.UserAgent(),
		RemoteAddr:         r.RemoteAddr,
		Host:               r.Host,
		Referer:            r.Header.Get("Referer"),
		ContentLength:      r.ContentLength,
		ContentType:        r.Header.Get("Content-Type"),
		ServerTime:         "",
		ServerTimeStampUTC: 0,
		OnewayTripTime:     -1,
		RoundTripTime:      -1, // Renamed field
		BodyTruncated:      false,
	}

	// Read the request body with size limit
	bodyReader := io.LimitReader(r.Body, MAX_BODY_SIZE+1)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
	} else {
		// Check if the body was truncated
		if int64(len(body)) > MAX_BODY_SIZE {
			info.Body = string(body[:MAX_BODY_SIZE])
			info.BodyTruncated = true
		} else {
			info.Body = string(body)
		}

		// Escape HTML for safety in HTML view
		info.Body = html.EscapeString(info.Body)
	}

	// Calculate trip time from Date header if present
	dateHeader := r.Header.Get("Date")
	if dateHeader != "" {
		clientTime, err := time.Parse(http.TimeFormat, dateHeader)
		if err == nil {
			info.OnewayTripTime = time.Since(clientTime).Milliseconds()
			// Calculate roundtrip time if response is sent back
			info.RoundTripTime = time.Since(clientTime).Milliseconds() * 2
		} else {
			log.Printf("Error parsing Date header: %v", err)
		}
	}

	// Extract cookies from the request
	for _, cookie := range r.Cookies() {
		info.Cookies[cookie.Name] = cookie.Value
	}

	// Get server information
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Error getting hostname: %v", err)
		hostname = "unknown"
	}
	info.ServerHostname = hostname
	info.ServerLocalIP = GetLocalIP()
	info.ServerVersion = embeddedVersion

	// Get the server date and time
	now := time.Now()
	info.ServerTime = now.Format(time.RFC3339)
	info.ServerTimeStampUTC = now.Unix()

	return info
}

func requestInfoHandler(w http.ResponseWriter, r *http.Request, clientIP string, rateLimiter *RateLimiter) {
	startTime := time.Now()

	// Collect request information
	info := collectRequestInfo(r, clientIP, rateLimiter)

	// Convert the info struct to JSON
	response, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error marshaling response: %v", err)
		return
	}

	// Set the response headers
	w.Header().Set("Content-Type", "application/json")

	// Add rate limit headers
	remaining := rateLimiter.GetRemainingRequests(clientIP)
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(RATE_LIMIT))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(RATE_WINDOW).Unix(), 10))

	// Add CORS headers
	EnableCORS(w)

	// Send the response
	w.Write(response)

	// Calculate and log request processing time
	processingTime := time.Since(startTime)
	log.Printf("Processed JSON request from %s %s %s in %v (remaining: %d/%d)",
		clientIP, r.Method, r.URL.String(), processingTime, remaining, RATE_LIMIT)
}
