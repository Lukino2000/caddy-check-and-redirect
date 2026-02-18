package checkandredirect

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CheckAndRedirect{})
}

// CheckAndRedirect implements an HTTP handler that reads a URL file,
// checks for redirects, and redirects incoming requests accordingly.
type CheckAndRedirect struct {
	// Path to the file containing URLs.
	File string `json:"file"`

	// HTTP status code to use for the redirect (301 or 302).
	Status int `json:"status"`

	// Number of minutes between each check.
	Schedule int `json:"schedule"`

	logger      *zap.Logger
	currentURL  string
	mu          sync.RWMutex
	stopChan    chan struct{}
	ticker      *time.Ticker
}

// CaddyModule returns the Caddy module information.
func (CheckAndRedirect) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.check_and_redirect",
		New: func() caddy.Module { return new(CheckAndRedirect) },
	}
}

// Provision sets up the module.
func (cr *CheckAndRedirect) Provision(ctx caddy.Context) error {
	cr.logger = ctx.Logger(cr)
	cr.stopChan = make(chan struct{})

	if cr.File == "" {
		return fmt.Errorf("check_and_redirect: file is required")
	}

	if cr.Status != 301 && cr.Status != 302 {
		return fmt.Errorf("check_and_redirect: status must be 301 or 302, got %d", cr.Status)
	}

	if cr.Schedule <= 0 {
		return fmt.Errorf("check_and_redirect: schedule must be greater than 0, got %d", cr.Schedule)
	}

	// Run the check immediately at startup.
	cr.runCheck()

	// Start the periodic ticker.
	cr.ticker = time.NewTicker(time.Duration(cr.Schedule) * time.Minute)
	go func() {
		for {
			select {
			case <-cr.ticker.C:
				cr.runCheck()
			case <-cr.stopChan:
				return
			}
		}
	}()

	cr.logger.Info("check_and_redirect provisioned",
		zap.String("file", cr.File),
		zap.Int("status", cr.Status),
		zap.Int("schedule_minutes", cr.Schedule),
	)

	return nil
}

// Validate ensures the module configuration is valid.
func (cr *CheckAndRedirect) Validate() error {
	if cr.File == "" {
		return fmt.Errorf("check_and_redirect: file is required")
	}
	if cr.Status != 301 && cr.Status != 302 {
		return fmt.Errorf("check_and_redirect: status must be 301 or 302")
	}
	if cr.Schedule <= 0 {
		return fmt.Errorf("check_and_redirect: schedule must be greater than 0")
	}
	return nil
}

// Cleanup stops the background goroutine.
func (cr *CheckAndRedirect) Cleanup() error {
	if cr.ticker != nil {
		cr.ticker.Stop()
	}
	if cr.stopChan != nil {
		close(cr.stopChan)
	}
	cr.logger.Info("check_and_redirect cleaned up")
	return nil
}

// ServeHTTP handles incoming requests by redirecting to the current URL.
func (cr *CheckAndRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	cr.mu.RLock()
	target := cr.currentURL
	cr.mu.RUnlock()

	if target == "" {
		cr.logger.Warn("check_and_redirect: no target URL available, passing to next handler")
		return next.ServeHTTP(w, r)
	}

	http.Redirect(w, r, target, cr.Status)
	return nil
}

// runCheck reads the last line of the file, checks the URL for redirects,
// and updates the current target URL.
func (cr *CheckAndRedirect) runCheck() {
	cr.logger.Info("check_and_redirect: running check")

	lastLine, err := cr.readLastLine()
	if err != nil {
		cr.logger.Error("check_and_redirect: failed to read last line from file",
			zap.String("file", cr.File),
			zap.Error(err),
		)
		return
	}

	if lastLine == "" {
		cr.logger.Warn("check_and_redirect: file is empty or has no valid lines",
			zap.String("file", cr.File),
		)
		return
	}

	// Parse the line: "2026-02-26T14:11:00;https://miosito.com"
	parts := strings.SplitN(lastLine, ";", 2)
	if len(parts) != 2 {
		cr.logger.Error("check_and_redirect: invalid line format, expected 'datetime;url'",
			zap.String("line", lastLine),
		)
		return
	}

	urlFromFile := strings.TrimSpace(parts[1])
	if urlFromFile == "" {
		cr.logger.Error("check_and_redirect: empty URL in line",
			zap.String("line", lastLine),
		)
		return
	}

	cr.logger.Info("check_and_redirect: checking URL",
		zap.String("url", urlFromFile),
	)

	// Make an HTTP request without following redirects.
	redirectURL, wasRedirected, err := cr.checkForRedirect(urlFromFile)
	if err != nil {
		// The site did not respond properly. Use the URL from the file.
		cr.logger.Warn("check_and_redirect: request failed, using URL from file",
			zap.String("url", urlFromFile),
			zap.Error(err),
		)
		cr.mu.Lock()
		cr.currentURL = urlFromFile
		cr.mu.Unlock()
		return
	}

	if !wasRedirected {
		// No redirect, use the URL from the file as-is.
		cr.logger.Info("check_and_redirect: no redirect detected, using URL from file",
			zap.String("url", urlFromFile),
		)
		cr.mu.Lock()
		cr.currentURL = urlFromFile
		cr.mu.Unlock()
		return
	}

	// The site responded with a redirect. Append the new URL to the file.
	cr.logger.Info("check_and_redirect: redirect detected",
		zap.String("from", urlFromFile),
		zap.String("to", redirectURL),
	)

	newLine := fmt.Sprintf("%s;%s", time.Now().Format("2006-01-02T15:04:05"), redirectURL)
	err = cr.appendLine(newLine)
	if err != nil {
		cr.logger.Error("check_and_redirect: failed to append new line to file",
			zap.String("file", cr.File),
			zap.Error(err),
		)
	}

	cr.mu.Lock()
	cr.currentURL = redirectURL
	cr.mu.Unlock()
}

// readLastLine reads the last non-empty line from the file.
func (cr *CheckAndRedirect) readLastLine() (string, error) {
	f, err := os.Open(cr.File)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lastLine = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to scan file: %w", err)
	}

	return lastLine, nil
}

// appendLine appends a line to the file.
func (cr *CheckAndRedirect) appendLine(line string) error {
	f, err := os.OpenFile(cr.File, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString("\n" + line)
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

// checkForRedirect makes an HTTP GET request to the given URL without following
// redirects. Returns the redirect location and whether a redirect was detected.
func (cr *CheckAndRedirect) checkForRedirect(targetURL string) (string, bool, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		// Do not follow redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return "", false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response is a redirect (3xx).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			// Redirect status but no Location header, treat as no redirect.
			return "", false, nil
		}
		return location, true, nil
	}

	// Not a redirect.
	return "", false, nil
}

// Interface guards.
var (
	_ caddy.Module                = (*CheckAndRedirect)(nil)
	_ caddy.Provisioner           = (*CheckAndRedirect)(nil)
	_ caddy.Validator             = (*CheckAndRedirect)(nil)
	_ caddy.CleanerUpper          = (*CheckAndRedirect)(nil)
	_ caddyhttp.MiddlewareHandler = (*CheckAndRedirect)(nil)
)
