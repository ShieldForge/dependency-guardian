// Package upstream provides shared HTTP utilities for ecosystem handlers.
// It eliminates the duplicated proxy-passthrough and upstream-fetch logic
// across the npm, PyPI, and Go module handlers.
package upstream

import (
	"io"
	"net/http"
	"time"
)

// Client wraps an HTTP client with the upstream base URL.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new upstream client.
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: timeout},
	}
}

// Fetch performs a GET request to the upstream and returns the body bytes
// and status code. The caller does not need to close anything.
func (c *Client) Fetch(r *http.Request, path string) ([]byte, int, error) {
	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// Passthrough forwards the request to the upstream without modification
// and copies the response back to the client. Suitable for tarball,
// wheel, .mod, and .zip downloads.
func (c *Client) Passthrough(w http.ResponseWriter, r *http.Request) {
	url := c.BaseURL + r.URL.Path

	var bodyReader io.Reader
	if r.Body != nil {
		bodyReader = r.Body
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bodyReader)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Copy relevant headers.
	for _, hdr := range []string{"Accept", "Accept-Encoding", "Authorization"} {
		if v := r.Header.Get(hdr); v != "" {
			req.Header.Set(hdr, v)
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
