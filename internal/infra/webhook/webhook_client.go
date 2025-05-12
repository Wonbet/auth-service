package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type WebhookClient struct {
	webhookURL   string
	httpClient   *http.Client
	allowedHosts []string
}

type IPChangeNotification struct {
	UserID    string    `json:"user_id"`
	OldIP     string    `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	Timestamp time.Time `json:"timestamp"`
}

func NewWebhookClient(webhookURL string, allowedHosts []string) *WebhookClient {
	return &WebhookClient{
		webhookURL: webhookURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		allowedHosts: allowedHosts,
	}
}

func (c *WebhookClient) validateURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	if len(c.allowedHosts) > 0 {
		hostAllowed := false
		for _, allowedHost := range c.allowedHosts {
			if strings.EqualFold(parsedURL.Hostname(), allowedHost) {
				hostAllowed = true
				break
			}
		}
		if !hostAllowed {
			return fmt.Errorf("host not in allowed list: %s", parsedURL.Hostname())
		}
	}

	host := parsedURL.Hostname()
	if host != "localhost" && host != "127.0.0.1" {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return fmt.Errorf("URL resolves to private/local IP address: %s", ip.String())
				}
			}
		}
	}

	return nil
}

func (c *WebhookClient) NotifyNewIP(userID uuid.UUID, oldIP, newIP string) error {
	if err := c.validateURL(c.webhookURL); err != nil {
		return fmt.Errorf("webhook URL validation failed: %w", err)
	}

	notification := IPChangeNotification{
		UserID:    userID.String(),
		OldIP:     oldIP,
		NewIP:     newIP,
		Timestamp: time.Now(),
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	req, err := http.NewRequest("POST", c.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}
