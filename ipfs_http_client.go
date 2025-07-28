// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// IPFSHTTPClient provides a lightweight HTTP client for IPFS API calls
type IPFSHTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

func parseMultiaddr(multiaddr string) (string, error) {
	parts := strings.Split(multiaddr, "/")
	var ip, port string

	for i, part := range parts {
		if part == "ip4" && i < len(parts)-1 {
			ip = parts[i+1]
		}
		if part == "tcp" && i < len(parts)-1 {
			port = parts[i+1]
		}
	}

	if ip == "" {
		return "", errors.New("multiaddr: no IP found")
	}

	if port == "" {
		return "", errors.New("multiaddr: no port found")
	}

	return fmt.Sprintf("http://%s:%s", ip, port), nil
}

// NewIPFSHTTPClient creates a new lightweight IPFS HTTP client
func NewIPFSHTTPClient(apiAddr string) (*IPFSHTTPClient, error) {
	var baseURL string
	var err error
	if strings.HasPrefix(apiAddr, "http") {
		baseURL = apiAddr
	} else if strings.HasPrefix(apiAddr, "/ip4/") {
		// try multiaddr format
		baseURL, err = parseMultiaddr(apiAddr)
		if err != nil {
			return nil, fmt.Errorf("NewIPFSHTTPClient: failed to parse %q: %w", apiAddr, err)
		}
	} else {
		return nil, fmt.Errorf("NewIPFSHTTPClient: unhandled url type: %q", apiAddr)
	}
	log("NewIPFSHTTPClient address=%s", baseURL)
	return &IPFSHTTPClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// AddResponse represents the response from IPFS add API
type AddResponse struct {
	Name string `json:"Name"`
	Hash string `json:"Hash"`
	Size string `json:"Size"`
}

// Add uploads data to IPFS and returns the CID
func (c *IPFSHTTPClient) Add(ctx context.Context, data io.Reader) (string, error) {
	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create form file
	part, err := writer.CreateFormFile("file", "data")
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %w", err)
	}

	// Copy data to form
	_, err = io.Copy(part, data)
	if err != nil {
		return "", fmt.Errorf("failed to copy data: %w", err)
	}

	// Close writer
	err = writer.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v0/add", &buf)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("IPFS add failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var addResp AddResponse
	if err := json.NewDecoder(resp.Body).Decode(&addResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return addResp.Hash, nil
}

// Cat retrieves data from IPFS by CID
func (c *IPFSHTTPClient) Cat(ctx context.Context, cid string) (io.ReadCloser, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v0/cat", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add CID as query parameter
	q := req.URL.Query()
	q.Add("arg", cid)
	req.URL.RawQuery = q.Encode()

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("IPFS cat failed with status %d: %s", resp.StatusCode, string(body))
	}

	return resp.Body, nil
}

// CatWithSize retrieves data from IPFS by CID and attempts to get size from Content-Length header
func (c *IPFSHTTPClient) CatWithSize(ctx context.Context, cid string) (io.ReadCloser, int64, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v0/cat", nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add CID as query parameter
	q := req.URL.Query()
	q.Add("arg", cid)
	req.URL.RawQuery = q.Encode()

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, 0, fmt.Errorf("IPFS cat failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Try to get size from Content-Length header
	var size int64 = -1 // -1 indicates unknown size
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if parsedSize, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			size = parsedSize
		}
	}

	return resp.Body, size, nil
}

// SwarmPeersResponse represents a peer in the swarm
type SwarmPeersResponse struct {
	Peers []struct {
		Addr string `json:"Addr"`
		Peer string `json:"Peer"`
	} `json:"Peers"`
}

// SwarmPeers returns the list of swarm peers
func (c *IPFSHTTPClient) SwarmPeers(ctx context.Context) ([]string, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v0/swarm/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IPFS swarm peers failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var peersResp SwarmPeersResponse
	if err := json.NewDecoder(resp.Body).Decode(&peersResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to string slice
	peers := make([]string, len(peersResp.Peers))
	for i, peer := range peersResp.Peers {
		peers[i] = peer.Addr
	}

	return peers, nil
}

// IPFSFile represents a file for IPFS operations
type IPFSFile struct {
	reader io.Reader
	size   int64
}

// NewIPFSFile creates a new IPFS file from a reader
func NewIPFSFile(reader io.Reader) *IPFSFile {
	return &IPFSFile{reader: reader}
}

// NewIPFSFileFromBytes creates a new IPFS file from bytes
func NewIPFSFileFromBytes(data []byte) *IPFSFile {
	return &IPFSFile{
		reader: bytes.NewReader(data),
		size:   int64(len(data)),
	}
}

// Read implements io.Reader
func (f *IPFSFile) Read(p []byte) (n int, err error) {
	return f.reader.Read(p)
}

// Size returns the file size if known
func (f *IPFSFile) Size() int64 {
	return f.size
}

// Compatibility wrapper functions to match the original API

// LightweightIPFSClient wraps the HTTP client with methods similar to the original
type LightweightIPFSClient struct {
	client *IPFSHTTPClient
}

// NewLightweightIPFSClient creates a new lightweight IPFS client
func NewLightweightIPFSClient(apiAddr string) (*LightweightIPFSClient, error) {
	client, err := NewIPFSHTTPClient(apiAddr)
	if err != nil {
		return nil, err
	}
	return &LightweightIPFSClient{client: client}, nil
}

// UnixfsAPI provides UnixFS operations
type UnixfsAPI struct {
	client *IPFSHTTPClient
}

// Unixfs returns the UnixFS API
func (c *LightweightIPFSClient) Unixfs() *UnixfsAPI {
	return &UnixfsAPI{client: c.client}
}

// IPFSPath represents an IPFS path
type IPFSPath struct {
	cid string
}

// NewIPFSPath creates a new IPFS path
func NewIPFSPath(pathStr string) (*IPFSPath, error) {
	// Extract CID from path (e.g., "/ipfs/QmXXX" -> "QmXXX")
	if len(pathStr) > 6 && pathStr[:6] == "/ipfs/" {
		return &IPFSPath{cid: pathStr[6:]}, nil
	}
	return &IPFSPath{cid: pathStr}, nil
}

// String returns the path as a string
func (p *IPFSPath) String() string {
	return p.cid
}

// Add adds a file to IPFS
func (u *UnixfsAPI) Add(ctx context.Context, file *IPFSFile) (*IPFSPath, error) {
	cid, err := u.client.Add(ctx, file)
	if err != nil {
		return nil, err
	}
	return &IPFSPath{cid: cid}, nil
}

// IPFSNode represents a node in IPFS
type IPFSNode struct {
	reader io.ReadCloser
	size   int64
}

// Size returns the node size
func (n *IPFSNode) Size() (int64, error) {
	return n.size, nil
}

// Read implements io.Reader
func (n *IPFSNode) Read(p []byte) (int, error) {
	return n.reader.Read(p)
}

// Close implements io.Closer
func (n *IPFSNode) Close() error {
	return n.reader.Close()
}

// Get retrieves a file from IPFS
func (u *UnixfsAPI) Get(ctx context.Context, path *IPFSPath) (*IPFSNode, error) {
	reader, size, err := u.client.CatWithSize(ctx, path.cid)
	if err != nil {
		return nil, err
	}
	return &IPFSNode{reader: reader, size: size}, nil
}

// SwarmAPI provides swarm operations
type SwarmAPI struct {
	client *IPFSHTTPClient
}

// Swarm returns the Swarm API
func (c *LightweightIPFSClient) Swarm() *SwarmAPI {
	return &SwarmAPI{client: c.client}
}

// Peers returns the swarm peers
func (s *SwarmAPI) Peers(ctx context.Context) ([]string, error) {
	return s.client.SwarmPeers(ctx)
}
