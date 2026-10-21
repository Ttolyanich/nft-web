package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

var (
	appConfigFile = flag.String("conf", "/etc/nft-web.conf", "Path to nft-web configuration file")
	nftConfigFile = flag.String("nft-conf", "/etc/nftables.conf", "Path to nftables.conf")
	listenAddr    = flag.String("listen", ":8443", "Address to listen on")
	authPassword  = flag.String("pass", "", "Admin password")
	allowedIPs    = flag.String("allow-ips", "", "Allowed client IPs")
	configMutex   sync.Mutex
)

type AppSettings struct {
	ListenAddr   string   `json:"listen"`
	PasswordHash string   `json:"password_hash"`
	AllowedIPs   []string `json:"allowed_ips"`
	NFTConfig    string   `json:"nft_config"`
}

var (
	settings        AppSettings
	parsedIPNets    []*net.IPNet
	activeSessions  = make(map[string]time.Time)
	sessionMutex    sync.Mutex
	loginAttempts   = make(map[string][]time.Time)
	attemptsMutex   sync.Mutex
)

// Generate SHA256 hex hash
func hashPassword(pass string) string {
	h := sha256.Sum256([]byte(pass))
	return hex.EncodeToString(h[:])
}

// Generate random secure token
func generateToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadSettings() {
	flag.Parse()

	// Default values
	settings = AppSettings{
		ListenAddr: *listenAddr,
		NFTConfig:  *nftConfigFile,
		AllowedIPs: []string{},
	}

	// Try reading /etc/nft-web.conf if exists
	if data, err := os.ReadFile(*appConfigFile); err == nil {
		json.Unmarshal(data, &settings)
	}

	// Override with flags if provided
	if *authPassword != "" {
		settings.PasswordHash = hashPassword(*authPassword)
	}

	// Fallback generate password if none exists
	if settings.PasswordHash == "" {
		defaultPass := "Admin_" + strconv.FormatInt(time.Now().Unix()%100000, 10)
		settings.PasswordHash = hashPassword(defaultPass)
		log.Printf("\n[SECURITY] Ни один пароль не задан. Сгенерирован временный пароль: %s\n", defaultPass)
		saveSettings()
	}

	// Parse allowed IPs
	parsedIPNets = nil
	for _, raw := range settings.AllowedIPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			raw = raw + "/32"
		}
		if _, ipNet, err := net.ParseCIDR(raw); err == nil {
			parsedIPNets = append(parsedIPNets, ipNet)
		}
	}
}

func saveSettings() error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*appConfigFile, data, 0600)
}

func sanitizeComment(s string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9а-яА-ЯёЁ\s\-_\.]`)
	clean := reg.ReplaceAllString(s, "")
	if len(clean) > 40 {
		return clean[:40]
	}
	return clean
}

func getClientIP(r *http.Request) string {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		clientIP = strings.TrimSpace(parts[0])
	}
	return clientIP
}

// Rate Limiter: max 5 failed attempts in 10 minutes
func isRateLimited(ip string) bool {
	attemptsMutex.Lock()
	defer attemptsMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)

	var valid []time.Time
	for _, t := range loginAttempts[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	loginAttempts[ip] = valid
	return len(valid) >= 5
}

func recordFailedAttempt(ip string) {
	attemptsMutex.Lock()
	defer attemptsMutex.Unlock()
	loginAttempts[ip] = append(loginAttempts[ip], time.Now())
}

func clearAttempts(ip string) {
	attemptsMutex.Lock()
	defer attemptsMutex.Unlock()
	delete(loginAttempts, ip)
}

// Session check
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("nft_session")
	if err != nil || cookie.Value == "" {
		return false
	}

	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	exp, ok := activeSessions[cookie.Value]
	if !ok || time.Now().After(exp) {
		delete(activeSessions, cookie.Value)
		return false
	}
	return true
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. IP Filter check
		if len(parsedIPNets) > 0 {
			clientIP := net.ParseIP(getClientIP(r))
			allowed := false
			for _, ipNet := range parsedIPNets {
				if ipNet.Contains(clientIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Доступ запрещен: ваш IP не входит в список разрешенных", http.StatusForbidden)
				return
			}
		}

		// 2. Session verification
		if !isAuthenticated(r) {
			jsonError(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, statusCode int) {
	jsonResponse(w, map[string]string{"error": msg}, statusCode)
}

// -------------------------------------------------------------
// AUTH ENDPOINTS (PASSWORD ONLY)
// -------------------------------------------------------------
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	if isRateLimited(clientIP) {
		jsonError(w, "Слишком много неудачных попыток. Доступ временно заблокирован на 10 минут.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		jsonError(w, "Введите пароль", http.StatusBadRequest)
		return
	}

	inputHash := hashPassword(req.Password)
	if subtle.ConstantTimeCompare([]byte(inputHash), []byte(settings.PasswordHash)) != 1 {
		recordFailedAttempt(clientIP)
		jsonError(w, "Неверный пароль администратора", http.StatusUnauthorized)
		return
	}

	clearAttempts(clientIP)

	// Create session
	token := generateToken(32)
	sessionMutex.Lock()
	activeSessions[token] = time.Now().Add(24 * time.Hour)
	sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "nft_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("nft_session"); err == nil {
		sessionMutex.Lock()
		delete(activeSessions, cookie.Value)
		sessionMutex.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "nft_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]bool{"authenticated": isAuthenticated(r)}, http.StatusOK)
}

// -------------------------------------------------------------
// STATUS
// -------------------------------------------------------------
func handleStatus(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	fwdBytes, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	isForwarding := false
	if err == nil && strings.TrimSpace(string(fwdBytes)) == "1" {
		isForwarding = true
	}

	type IfaceInfo struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		MAC  string `json:"mac"`
		IsUp bool   `json:"is_up"`
	}
	var ifaces []IfaceInfo

	netIfaces, err := net.Interfaces()
	if err == nil {
		for _, ifi := range netIfaces {
			if ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			info := IfaceInfo{
				Name: ifi.Name,
				MAC:  ifi.HardwareAddr.String(),
				IsUp: ifi.Flags&net.FlagUp != 0,
			}
			addrs, _ := ifi.Addrs()
			var ipList []string
			for _, a := range addrs {
				ipList = append(ipList, a.String())
			}
			info.IP = strings.Join(ipList, ", ")
			ifaces = append(ifaces, info)
		}
	}

	whitelist, _ := parseWhitelistFromConfig(settings.NFTConfig)
	forwards, _ := parseForwardsFromConfig(settings.NFTConfig)

	f2bActive := false
	if out, err := exec.Command("systemctl", "is-active", "fail2ban").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "active" {
			f2bActive = true
		}
	}

	jsonResponse(w, map[string]interface{}{
		"hostname":        hostname,
		"ip_forward":      isForwarding,
		"whitelist_count": len(whitelist),
		"forwards_count":  len(forwards),
		"fail2ban_active": f2bActive,
		"interfaces":      ifaces,
	}, http.StatusOK)
}

// -------------------------------------------------------------
// WHITELIST (@admin_ips)
// -------------------------------------------------------------
type WhitelistItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func parseWhitelistFromConfig(path string) ([]WhitelistItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var items []WhitelistItem
	reSet := regexp.MustCompile(`(?s)set\s+admin_ips\s*\{[^}]*elements\s*=\s*\{([^}]*)\}`)
	match := reSet.FindStringSubmatch(content)
	if len(match) > 1 {
		lines := strings.Split(match[1], "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "#", 2)
			ip := strings.Trim(strings.TrimSpace(parts[0]), ",;")
			comment := ""
			if len(parts) > 1 {
				comment = strings.TrimSpace(parts[1])
			}
			if ip != "" {
				items = append(items, WhitelistItem{IP: ip, Comment: comment})
			}
		}
	}
	return items, nil
}

func handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	items, err := parseWhitelistFromConfig(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Не удалось прочитать белый список: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"elements": items}, http.StatusOK)
}

func updateAdminIpsInContent(content string, items []WhitelistItem) string {
	var b strings.Builder
	b.WriteString("elements = {\n")
	b.WriteString("                        127.0.0.1,\n")
	for _, item := range items {
		if item.IP == "127.0.0.1" || item.IP == "" {
			continue
		}
		if item.Comment != "" {
			b.WriteString(fmt.Sprintf("                        %s,  # %s\n", item.IP, item.Comment))
		} else {
			b.WriteString(fmt.Sprintf("                        %s,\n", item.IP))
		}
	}
	b.WriteString("                }")

	reElements := regexp.MustCompile(`(?s)elements\s*=\s*\{[^}]*\}`)
	if reElements.MatchString(content) {
		return reElements.ReplaceAllString(content, b.String())
	}
	return content
}

func handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req WhitelistItem
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		jsonError(w, "Неверный IP адрес", http.StatusBadRequest)
		return
	}

	cleanIP := strings.TrimSpace(req.IP)
	if net.ParseIP(cleanIP) == nil && !strings.Contains(cleanIP, "/") {
		jsonError(w, "Некорректный формат IPv4 адреса", http.StatusBadRequest)
		return
	}
	req.Comment = sanitizeComment(req.Comment)

	// Read existing items
	items, _ := parseWhitelistFromConfig(settings.NFTConfig)
	alreadyExists := false
	for _, it := range items {
		if it.IP == cleanIP {
			alreadyExists = true
			break
		}
	}
	if !alreadyExists {
		items = append(items, WhitelistItem{IP: cleanIP, Comment: req.Comment})
	}

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Не удается прочитать конфиг", http.StatusInternalServerError)
		return
	}

	newContent := updateAdminIpsInContent(string(data), items)

	// Validate before saving
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_test_%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err == nil {
		defer os.Remove(tmpFile)
		if out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput(); err != nil {
			jsonError(w, "Ошибка синтаксиса NFT: "+string(out), http.StatusBadRequest)
			return
		}
	}

	os.WriteFile(settings.NFTConfig, []byte(newContent), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()

	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req WhitelistItem
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		jsonError(w, "Неверный IP", http.StatusBadRequest)
		return
	}

	cleanIP := strings.TrimSpace(req.IP)
	items, _ := parseWhitelistFromConfig(settings.NFTConfig)
	var newItems []WhitelistItem
	for _, it := range items {
		if it.IP != cleanIP && it.IP != "127.0.0.1" {
			newItems = append(newItems, it)
		}
	}

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения конфига", http.StatusInternalServerError)
		return
	}

	newContent := updateAdminIpsInContent(string(data), newItems)
	os.WriteFile(settings.NFTConfig, []byte(newContent), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()

	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// -------------------------------------------------------------
// INPUT RULES & TOGGLES (Защита шлюза + проверка конфликта 80/443)
// -------------------------------------------------------------
type InputToggles struct {
	AllowICMP      bool `json:"allow_icmp"`
	AllowOpenVPN   bool `json:"allow_openvpn"`
	AllowWireGuard bool `json:"allow_wireguard"`
	AllowHTTP      bool `json:"allow_http"`
	AllowHTTPS     bool `json:"allow_https"`
	HTTPConflict   bool `json:"http_conflict"`
	HTTPSConflict  bool `json:"https_conflict"`
	SSHMode        string `json:"ssh_mode"` // "admin_ips", "all"
}

type CustomInputRule struct {
	ID      string `json:"id"`
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Access  string `json:"access"` // "all", "admin", "lan"
	Comment string `json:"comment"`
}

func parseInputRules(path string) (InputToggles, []CustomInputRule, error) {
	var toggles InputToggles
	var custom []CustomInputRule

	data, err := os.ReadFile(path)
	if err != nil {
		return toggles, custom, err
	}
	content := string(data)

	// Check toggles
	if strings.Contains(content, "icmp type") && strings.Contains(content, "accept") {
		toggles.AllowICMP = true
	}
	if strings.Contains(content, "udp dport 1194 accept") {
		toggles.AllowOpenVPN = true
	}
	if strings.Contains(content, "udp dport 51820 accept") {
		toggles.AllowWireGuard = true
	}

	// HTTP / HTTPS on gateway
	reHTTP := regexp.MustCompile(`(?m)^\s*tcp dport 80 accept`)
	reHTTPS := regexp.MustCompile(`(?m)^\s*tcp dport 443 accept`)
	toggles.AllowHTTP = reHTTP.MatchString(content)
	toggles.AllowHTTPS = reHTTPS.MatchString(content)

	// Check if port 80 or 443 are forwarded in DNAT
	forwards, _ := parseForwardsFromConfig(path)
	for _, f := range forwards {
		if f.ExtPort == 80 {
			toggles.HTTPConflict = true
			toggles.AllowHTTP = false
		}
		if f.ExtPort == 443 {
			toggles.HTTPSConflict = true
			toggles.AllowHTTPS = false
		}
	}

	// SSH detection
	if strings.Contains(content, "ip saddr @admin_ips accept") {
		toggles.SSHMode = "admin_ips"
	}
	if strings.Contains(content, "tcp dport 22 accept") {
		toggles.SSHMode = "all"
	}
	if toggles.SSHMode == "" {
		toggles.SSHMode = "admin_ips"
	}

	// Custom input rules
	reInput := regexp.MustCompile(`(?m)^\s*(?:(ip saddr @admin_ips|iifname \$LAN)\s+)?(tcp|udp)\s+dport\s+(\d+)\s+accept(?:\s*#\s*(.*))?$`)
	matches := reInput.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		port, _ := strconv.Atoi(m[3])
		// skip standard ports handled by toggles (22, 80, 443, 1194, 51820)
		if port == 22 || port == 80 || port == 443 || port == 1194 || port == 51820 {
			continue
		}
		access := "all"
		if strings.Contains(m[1], "admin_ips") {
			access = "admin"
		} else if strings.Contains(m[1], "$LAN") {
			access = "lan"
		}
		comment := ""
		if len(m) > 4 {
			comment = strings.TrimSpace(m[4])
		}
		custom = append(custom, CustomInputRule{
			ID:      fmt.Sprintf("%s-%d", m[2], port),
			Proto:   m[2],
			Port:    port,
			Access:  access,
			Comment: comment,
		})
	}

	return toggles, custom, nil
}

func handleGetInputRules(w http.ResponseWriter, r *http.Request) {
	toggles, custom, err := parseInputRules(settings.NFTConfig)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"toggles": toggles,
		"custom":  custom,
	}, http.StatusOK)
}

func insertRuleAfterHook(content, chainName, rule string) string {
	pattern := fmt.Sprintf(`(?s)chain\s+%s\s*\{[^}]*?type\s+[^\n]+;\s*(?:policy\s+[^\n]+;)?\s*\n`, chainName)
	reHook := regexp.MustCompile(pattern)
	if loc := reHook.FindStringIndex(content); loc != nil {
		return content[:loc[1]] + rule + "\n" + content[loc[1]:]
	}
	return strings.Replace(content, "chain "+chainName+" {", "chain "+chainName+" {\n"+rule, 1)
}

func handleToggleInput(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req struct {
		Service string `json:"service"` // icmp, openvpn, wireguard, ssh, http, https
		Value   string `json:"value"`   // true/false or mode
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Неверные параметры", http.StatusBadRequest)
		return
	}

	forwards, _ := parseForwardsFromConfig(settings.NFTConfig)
	if req.Service == "http" && req.Value == "true" {
		for _, f := range forwards {
			if f.ExtPort == 80 {
				jsonError(w, "Невозможно включить порт 80: он уже проброшен через DNAT на внутренний сервер", http.StatusBadRequest)
				return
			}
		}
	}
	if req.Service == "https" && req.Value == "true" {
		for _, f := range forwards {
			if f.ExtPort == 443 {
				jsonError(w, "Невозможно включить порт 443: он уже проброшен через DNAT на внутренний сервер", http.StatusBadRequest)
				return
			}
		}
	}

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения конфигурации", http.StatusInternalServerError)
		return
	}
	content := string(data)

	switch req.Service {
	case "icmp":
		rule := "                icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded } accept"
		if req.Value == "true" {
			if !strings.Contains(content, "icmp type") {
				content = insertRuleAfterHook(content, "INPUT", rule)
			}
		} else {
			re := regexp.MustCompile(`(?m)^\s*icmp type [^\n]+\n`)
			content = re.ReplaceAllString(content, "")
		}
	case "http":
		rule := "                tcp dport 80 accept # Web HTTP"
		re := regexp.MustCompile(`(?m)^\s*tcp dport 80 accept[^\n]*\n`)
		content = re.ReplaceAllString(content, "")
		if req.Value == "true" {
			content = insertRuleAfterHook(content, "INPUT", rule)
		}
	case "https":
		rule := "                tcp dport 443 accept # Web HTTPS"
		re := regexp.MustCompile(`(?m)^\s*tcp dport 443 accept[^\n]*\n`)
		content = re.ReplaceAllString(content, "")
		if req.Value == "true" {
			content = insertRuleAfterHook(content, "INPUT", rule)
		}
	case "openvpn":
		rule := "                udp dport 1194 accept # OpenVPN"
		if req.Value == "true" {
			if !strings.Contains(content, "udp dport 1194") {
				content = insertRuleAfterHook(content, "INPUT", rule)
			}
		} else {
			re := regexp.MustCompile(`(?m)^\s*udp dport 1194 accept[^\n]*\n`)
			content = re.ReplaceAllString(content, "")
		}
	case "wireguard":
		rule := "                udp dport 51820 accept # WireGuard"
		if req.Value == "true" {
			if !strings.Contains(content, "udp dport 51820") {
				content = insertRuleAfterHook(content, "INPUT", rule)
			}
		} else {
			re := regexp.MustCompile(`(?m)^\s*udp dport 51820 accept[^\n]*\n`)
			content = re.ReplaceAllString(content, "")
		}
	case "ssh":
		reAll := regexp.MustCompile(`(?m)^\s*tcp dport 22 accept[^\n]*\n`)
		content = reAll.ReplaceAllString(content, "")
		if req.Value == "all" {
			content = insertRuleAfterHook(content, "INPUT", "                tcp dport 22 accept # SSH for all")
		}
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_toggle_%d.conf", time.Now().UnixNano()))
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	if out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput(); err != nil {
		jsonError(w, "Ошибка валидации синтаксиса: "+string(out), http.StatusBadRequest)
		return
	}

	os.WriteFile(settings.NFTConfig, []byte(content), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleAddInputRule(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req CustomInputRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Port <= 0 || req.Port > 65535 {
		jsonError(w, "Неверный номер порта (1-65535)", http.StatusBadRequest)
		return
	}
	if req.Proto != "tcp" && req.Proto != "udp" {
		req.Proto = "tcp"
	}
	req.Comment = sanitizeComment(req.Comment)

	prefix := ""
	if req.Access == "admin" {
		prefix = "ip saddr @admin_ips "
	} else if req.Access == "lan" {
		prefix = "iifname $LAN "
	}

	rule := fmt.Sprintf("                %s%s dport %d accept", prefix, req.Proto, req.Port)
	if req.Comment != "" {
		rule += " # " + req.Comment
	}

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения файла", http.StatusInternalServerError)
		return
	}
	content := string(data)

	content = insertRuleAfterHook(content, "INPUT", rule)

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_input_%d.conf", time.Now().UnixNano()))
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	if out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput(); err != nil {
		jsonError(w, "Ошибка синтаксиса: "+string(out), http.StatusBadRequest)
		return
	}

	os.WriteFile(settings.NFTConfig, []byte(content), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleDeleteInputRule(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		jsonError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	parts := strings.Split(req.ID, "-")
	if len(parts) != 2 {
		jsonError(w, "Некорректный ID", http.StatusBadRequest)
		return
	}
	proto := parts[0]
	port := parts[1]

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения файла", http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	inInputChain := false

	for _, l := range lines {
		if strings.Contains(l, "chain INPUT {") {
			inInputChain = true
		} else if inInputChain && strings.Contains(l, "}") {
			inInputChain = false
		}

		if inInputChain && strings.Contains(l, proto) && strings.Contains(l, "dport "+port) {
			continue
		}
		newLines = append(newLines, l)
	}

	newContent := strings.Join(newLines, "\n")
	os.WriteFile(settings.NFTConfig, []byte(newContent), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// -------------------------------------------------------------
// FAIL2BAN
// -------------------------------------------------------------
type Fail2banStatus struct {
	Active    bool     `json:"active"`
	Jails     []string `json:"jails"`
	BannedIPs []string `json:"banned_ips"`
	TotalBans int      `json:"total_bans"`
}

func handleGetFail2ban(w http.ResponseWriter, r *http.Request) {
	res := Fail2banStatus{
		Active:    false,
		Jails:     []string{},
		BannedIPs: []string{},
	}

	out, err := exec.Command("fail2ban-client", "status").CombinedOutput()
	if err != nil {
		jsonResponse(w, res, http.StatusOK)
		return
	}
	res.Active = true

	reJails := regexp.MustCompile(`Jail list:\s*(.+)`)
	mJails := reJails.FindStringSubmatch(string(out))
	if len(mJails) > 1 {
		rawJails := strings.Split(mJails[1], ",")
		for _, j := range rawJails {
			j = strings.TrimSpace(j)
			if j != "" {
				res.Jails = append(res.Jails, j)
			}
		}
	}

	for _, jail := range res.Jails {
		jOut, jErr := exec.Command("fail2ban-client", "status", jail).CombinedOutput()
		if jErr == nil {
			reBanned := regexp.MustCompile(`Banned IP list:\s*(.+)`)
			mBanned := reBanned.FindStringSubmatch(string(jOut))
			if len(mBanned) > 1 {
				ips := strings.Fields(mBanned[1])
				res.BannedIPs = append(res.BannedIPs, ips...)
			}
		}
	}
	res.TotalBans = len(res.BannedIPs)

	jsonResponse(w, res, http.StatusOK)
}

func handleFail2banUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Jail string `json:"jail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		jsonError(w, "Неверный IP", http.StatusBadRequest)
		return
	}
	cleanIP := strings.TrimSpace(req.IP)
	if net.ParseIP(cleanIP) == nil {
		jsonError(w, "Некорректный IP", http.StatusBadRequest)
		return
	}
	if req.Jail == "" {
		req.Jail = "sshd"
	}

	out, err := exec.Command("fail2ban-client", "set", req.Jail, "unbanip", cleanIP).CombinedOutput()
	if err != nil {
		jsonError(w, "Ошибка снятия бана: "+string(out), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleFail2banBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Jail string `json:"jail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		jsonError(w, "Неверный IP", http.StatusBadRequest)
		return
	}
	cleanIP := strings.TrimSpace(req.IP)
	if net.ParseIP(cleanIP) == nil {
		jsonError(w, "Некорректный IP адрес", http.StatusBadRequest)
		return
	}
	if req.Jail == "" {
		req.Jail = "sshd"
	}

	out, err := exec.Command("fail2ban-client", "set", req.Jail, "banip", cleanIP).CombinedOutput()
	if err != nil {
		jsonError(w, "Ошибка блокировки: "+string(out), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// -------------------------------------------------------------
// PORT FORWARDING (DNAT)
// -------------------------------------------------------------
type PortForward struct {
	ID      string `json:"id"`
	Proto   string `json:"proto"`
	ExtPort int    `json:"ext_port"`
	IntIP   string `json:"int_ip"`
	IntPort int    `json:"int_port"`
	Comment string `json:"comment"`
}

func parseForwardsFromConfig(path string) ([]PortForward, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)

	var list []PortForward
	re := regexp.MustCompile(`(?m)^\s*iifname\s+\$WAN\s+(tcp|udp)\s+dport\s+\{?\s*(\d+)\s*\}?\s+dnat\s+to\s+([0-9.]+):(\d+)(?:\s*#\s*(.*))?$`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		extPort, _ := strconv.Atoi(m[2])
		intPort, _ := strconv.Atoi(m[4])
		comment := ""
		if len(m) > 5 {
			comment = strings.TrimSpace(m[5])
		}
		list = append(list, PortForward{
			ID:      fmt.Sprintf("%s-%d", m[1], extPort),
			Proto:   m[1],
			ExtPort: extPort,
			IntIP:   m[3],
			IntPort: intPort,
			Comment: comment,
		})
	}
	return list, nil
}

func handleGetForwards(w http.ResponseWriter, r *http.Request) {
	list, err := parseForwardsFromConfig(settings.NFTConfig)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"forwards": list}, http.StatusOK)
}

func handleAddForward(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req PortForward
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ExtPort <= 0 || req.ExtPort > 65535 || req.IntPort <= 0 || req.IntPort > 65535 {
		jsonError(w, "Некорректный номер порта", http.StatusBadRequest)
		return
	}
	cleanIntIP := strings.TrimSpace(req.IntIP)
	if net.ParseIP(cleanIntIP) == nil {
		jsonError(w, "Некорректный IP назначения", http.StatusBadRequest)
		return
	}
	if req.Proto != "tcp" && req.Proto != "udp" {
		req.Proto = "tcp"
	}
	req.Comment = sanitizeComment(req.Comment)

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения файла конфигурации", http.StatusInternalServerError)
		return
	}
	content := string(data)

	// If forwarding port 80 or 443, disable local input rules for them
	if req.ExtPort == 80 {
		re := regexp.MustCompile(`(?m)^\s*tcp dport 80 accept[^\n]*\n`)
		content = re.ReplaceAllString(content, "")
	} else if req.ExtPort == 443 {
		re := regexp.MustCompile(`(?m)^\s*tcp dport 443 accept[^\n]*\n`)
		content = re.ReplaceAllString(content, "")
	}

	dnatRule := fmt.Sprintf("                iifname $WAN %s dport %d dnat to %s:%d", req.Proto, req.ExtPort, cleanIntIP, req.IntPort)
	if req.Comment != "" {
		dnatRule += " # " + req.Comment
	}

	rePrerouting := regexp.MustCompile(`(?s)chain\s+PREROUTING\s*\{[^}]*priority\s+dstnat;[^\n]*\n`)
	locPrerouting := rePrerouting.FindStringIndex(content)
	if locPrerouting == nil {
		jsonError(w, "Цепочка PREROUTING не найдена", http.StatusBadRequest)
		return
	}
	content = content[:locPrerouting[1]] + dnatRule + "\n" + content[locPrerouting[1]:]

	forwardRule := fmt.Sprintf("                ip daddr %s %s dport %d accept", cleanIntIP, req.Proto, req.IntPort)
	if req.Comment != "" {
		forwardRule += " # " + req.Comment
	}

	reForward := regexp.MustCompile(`(?s)chain\s+FORWARD\s*\{[^}]*priority\s+filter;[^\n]*\n`)
	if locForward := reForward.FindStringIndex(content); locForward != nil {
		content = content[:locForward[1]] + forwardRule + "\n" + content[locForward[1]:]
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_test_%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		jsonError(w, "Ошибка создания временного файла", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		jsonError(w, "Ошибка синтаксиса NFT: "+string(out), http.StatusBadRequest)
		return
	}

	os.WriteFile(settings.NFTConfig+".bak", data, 0644)
	if err := os.WriteFile(settings.NFTConfig, []byte(content), 0644); err != nil {
		jsonError(w, "Ошибка записи файла: "+err.Error(), http.StatusInternalServerError)
		return
	}

	exec.Command("nft", "-f", settings.NFTConfig).Run()
	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

func handleDeleteForward(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		jsonError(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	parts := strings.Split(req.ID, "-")
	if len(parts) != 2 {
		jsonError(w, "Некорректный ID", http.StatusBadRequest)
		return
	}
	proto := parts[0]
	port := parts[1]

	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения конфига", http.StatusInternalServerError)
		return
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	for _, l := range lines {
		if strings.Contains(l, proto) && strings.Contains(l, "dport "+port) {
			continue
		}
		newLines = append(newLines, l)
	}

	newContent := strings.Join(newLines, "\n")
	os.WriteFile(settings.NFTConfig, []byte(newContent), 0644)
	exec.Command("nft", "-f", settings.NFTConfig).Run()

	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// -------------------------------------------------------------
// CONFIG EDITOR
// -------------------------------------------------------------
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(settings.NFTConfig)
	if err != nil {
		jsonError(w, "Ошибка чтения файла: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]string{"content": string(data)}, http.StatusOK)
}

func handleTestConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_test_%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(req.Content), 0644); err != nil {
		jsonError(w, "Ошибка создания временного файла", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		jsonResponse(w, map[string]interface{}{"valid": false, "error": string(out)}, http.StatusOK)
		return
	}
	jsonResponse(w, map[string]interface{}{"valid": true}, http.StatusOK)
}

func handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	configMutex.Lock()
	defer configMutex.Unlock()

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nft_apply_%d.conf", time.Now().UnixNano()))
	os.WriteFile(tmpFile, []byte(req.Content), 0644)
	defer os.Remove(tmpFile)

	out, err := exec.Command("nft", "-c", "-f", tmpFile).CombinedOutput()
	if err != nil {
		jsonError(w, "Ошибка в синтаксисе nftables:\n"+string(out), http.StatusBadRequest)
		return
	}

	if orig, err := os.ReadFile(settings.NFTConfig); err == nil {
		os.WriteFile(settings.NFTConfig+".bak", orig, 0644)
	}

	if err := os.WriteFile(settings.NFTConfig, []byte(req.Content), 0644); err != nil {
		jsonError(w, "Ошибка сохранения файла: "+err.Error(), http.StatusInternalServerError)
		return
	}

	applyOut, applyErr := exec.Command("nft", "-f", settings.NFTConfig).CombinedOutput()
	if applyErr != nil {
		jsonError(w, "Ошибка загрузки правил в ядро: "+string(applyOut), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]bool{"success": true}, http.StatusOK)
}

// -------------------------------------------------------------
// NAT CONNECTIONS
// -------------------------------------------------------------
type ConntrackSession struct {
	Proto   string `json:"proto"`
	Src     string `json:"src"`
	Sport   string `json:"sport"`
	Dst     string `json:"dst"`
	Dport   string `json:"dport"`
	State   string `json:"state"`
	Timeout string `json:"timeout"`
}

func handleGetConnections(w http.ResponseWriter, r *http.Request) {
	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		jsonResponse(w, map[string]interface{}{"connections": []ConntrackSession{}}, http.StatusOK)
		return
	}
	defer file.Close()

	var sessions []ConntrackSession
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() && count < 100 {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := fields[2]
		sess := ConntrackSession{Proto: proto}

		for _, f := range fields {
			if strings.HasPrefix(f, "src=") && sess.Src == "" {
				sess.Src = strings.TrimPrefix(f, "src=")
			} else if strings.HasPrefix(f, "dst=") && sess.Dst == "" {
				sess.Dst = strings.TrimPrefix(f, "dst=")
			} else if strings.HasPrefix(f, "sport=") && sess.Sport == "" {
				sess.Sport = strings.TrimPrefix(f, "sport=")
			} else if strings.HasPrefix(f, "dport=") && sess.Dport == "" {
				sess.Dport = strings.TrimPrefix(f, "dport=")
			}
		}

		if proto == "tcp" && len(fields) > 5 {
			sess.State = fields[5]
		}
		if len(fields) > 4 {
			sess.Timeout = fields[4]
		}

		if sess.Src != "" && sess.Dst != "" {
			sessions = append(sessions, sess)
			count++
		}
	}

	jsonResponse(w, map[string]interface{}{"connections": sessions}, http.StatusOK)
}

func main() {
	loadSettings()

	mux := http.NewServeMux()

	// Static UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		indexData, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "Страница не найдена", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexData)
	})

	// Public Auth endpoints
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/auth-status", handleAuthStatus)

	// Protected API
	mux.HandleFunc("/api/status", authMiddleware(handleStatus))
	mux.HandleFunc("/api/whitelist", authMiddleware(handleGetWhitelist))
	mux.HandleFunc("/api/whitelist/add", authMiddleware(handleAddWhitelist))
	mux.HandleFunc("/api/whitelist/delete", authMiddleware(handleDeleteWhitelist))
	
	mux.HandleFunc("/api/input-rules", authMiddleware(handleGetInputRules))
	mux.HandleFunc("/api/input-rules/toggle", authMiddleware(handleToggleInput))
	mux.HandleFunc("/api/input-rules/add", authMiddleware(handleAddInputRule))
	mux.HandleFunc("/api/input-rules/delete", authMiddleware(handleDeleteInputRule))

	mux.HandleFunc("/api/fail2ban", authMiddleware(handleGetFail2ban))
	mux.HandleFunc("/api/fail2ban/unban", authMiddleware(handleFail2banUnban))
	mux.HandleFunc("/api/fail2ban/ban", authMiddleware(handleFail2banBan))

	mux.HandleFunc("/api/forwards", authMiddleware(handleGetForwards))
	mux.HandleFunc("/api/forwards/add", authMiddleware(handleAddForward))
	mux.HandleFunc("/api/forwards/delete", authMiddleware(handleDeleteForward))
	
	mux.HandleFunc("/api/config", authMiddleware(handleGetConfig))
	mux.HandleFunc("/api/config/test", authMiddleware(handleTestConfig))
	mux.HandleFunc("/api/config/apply", authMiddleware(handleApplyConfig))
	mux.HandleFunc("/api/connections", authMiddleware(handleGetConnections))

	log.Printf("[INFO] NFT-GW Web Manager запущен на http://%s (Конфиг: %s)", settings.ListenAddr, *appConfigFile)
	if err := http.ListenAndServe(settings.ListenAddr, mux); err != nil {
		log.Fatalf("[FATAL] ListenAndServe: %v", err)
	}
}
