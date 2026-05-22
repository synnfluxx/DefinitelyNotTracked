package configs

import (
	"DefinitelyNotTracked/internal/domain"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func ParseSubscriptionURL(url string) ([]string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "v2rayN/6.42 sing-box/1.8.4 v2rayTun")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while parsing subscription url: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	b64data := string(body)
	links, err := domain.DecodeBase64Sub(b64data)
	if err != nil {
		return nil, err
	}

	return parseConfigs(links), nil
}

func ParseVless(vlessURL string) (*domain.VPNConfig, error) {
	u, err := url.Parse(strings.TrimSpace(vlessURL))
	if err != nil {
		return nil, err
	}

	if u.Scheme != "vless" {
		return nil, fmt.Errorf("неверный протокол: %s", u.Scheme)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		port = 443
	}

	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}

	name, _ = url.QueryUnescape(name)

	config := &domain.VPNConfig{
		Type: "vless",
		Name: name,
		Addr: u.Hostname(),
		Port: port,
		UUID: u.User.Username(),
	}

	// Все остальные параметры (security, reality public key, sni)
	// находятся в u.Query(). Например:
	// query := u.Query()
	// sni := query.Get("sni")

	return config, nil
}

func ParseVmess(vmessURL string) (*domain.VPNConfig, error) {
	if !strings.HasPrefix(vmessURL, "vmess://") {
		return nil, fmt.Errorf("неверный протокол vmess")
	}

	b64Data := vmessURL[8:]
	b64Data = strings.TrimSpace(b64Data)

	if len(b64Data)%4 != 0 {
		b64Data += strings.Repeat("=", 4-(len(b64Data)%4))
	}

	jsonData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		jsonData, err = base64.URLEncoding.DecodeString(b64Data)
		if err != nil {
			return nil, fmt.Errorf("ошибка b64 vmess: %v", err)
		}
	}

	var vKey domain.VMessJSON
	if err := json.Unmarshal(jsonData, &vKey); err != nil {
		return nil, fmt.Errorf("ошибка парсинга JSON vmess: %v", err)
	}

	var intPort int
	switch v := vKey.Port.(type) {
	case float64:
		intPort = int(v)
	case string:
		intPort, _ = strconv.Atoi(v)
	default:
		intPort = 443
	}

	config := &domain.VPNConfig{
		Type: "vmess",
		Name: vKey.Ps,
		Addr: vKey.Add,
		Port: intPort,
		UUID: vKey.ID,
	}

	return config, nil
}

func ParseLinkToConfig(url string) (*domain.VPNConfig, error) {
	switch {
	case strings.HasPrefix(url, "vless://") || strings.HasPrefix(url, "trojan://") || strings.HasPrefix(url, "ss://"):
		config, err := ParseVless(url)
		if err != nil {
			return nil, err
		}

		return config, nil
	case strings.HasPrefix(url, "vmess://"):
		config, err := ParseVmess(url)
		if err != nil {
			return nil, err
		}

		return config, nil
	}

	return nil, fmt.Errorf("invalid link type. must be vless or vmess")
}

func parseConfigs(decodedData string) []string {
	decodedData = strings.ReplaceAll(decodedData, "\r\n", "\n")
	lines := strings.Split(decodedData, "\n")
	var validConfigs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "vless://") ||
			strings.HasPrefix(line, "vmess://") ||
			strings.HasPrefix(line, "trojan://") ||
			strings.HasPrefix(line, "ss://") {
			validConfigs = append(validConfigs, line)
		}
	}
	return validConfigs
}

func ParseLinksToConfig(urls []string) ([]*domain.VPNConfig, error) {
	var result []*domain.VPNConfig
	for _, v := range urls {
		switch {
		case strings.HasPrefix(v, "vless://") || strings.HasPrefix(v, "trojan://") || strings.HasPrefix(v, "ss://"):
			config, err := ParseVless(v)
			if err != nil {
				return nil, err
			}

			result = append(result, config)
		case strings.HasPrefix(v, "vmess://"):
			config, err := ParseVmess(v)
			if err != nil {
				return nil, err
			}

			result = append(result, config)
		}
	}

	return result, nil
}
