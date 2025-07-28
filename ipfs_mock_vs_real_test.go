// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	tassert "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockClient creates a client using the mock IPFS server
func setupMockClient(t *testing.T) *LightweightIPFSClient {
	server := setupMockIPFSServer()
	t.Cleanup(server.Close)

	client, err := NewLightweightIPFSClient(server.URL)
	require.NoError(t, err)
	return client
}

// setupRealClient creates a client using a real IPFS node (if available)
func setupRealClient(t *testing.T) *LightweightIPFSClient {
	ipfsAPIPath := os.Getenv("IPFS_API_PATH")
	if ipfsAPIPath == "" {
		t.Skip("IPFS_API_PATH not set - skipping real IPFS tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := getIpfsClient(ctx, 0, nil)
	if err != nil {
		t.Skipf("Could not connect to real IPFS node: %v", err)
	}

	return client
}

func TestIPFSMockVsReal(t *testing.T) {
	testData := []byte("test content for comparison")

	t.Run("Upload and retrieve content - Mock vs Real", func(t *testing.T) {
		mockClient := setupMockClient(t)

		// Upload to mock
		mockFile := NewIPFSFileFromBytes(testData)
		mockPath, err := mockClient.Unixfs().Add(context.Background(), mockFile)
		require.NoError(t, err)

		// Try to retrieve from mock
		mockNode, err := mockClient.Unixfs().Get(context.Background(), mockPath)
		require.NoError(t, err)
		defer mockNode.Close()

		mockContent, err := io.ReadAll(mockNode)
		require.NoError(t, err)

		mockSize, err := mockNode.Size()
		require.NoError(t, err)

		t.Logf("Mock - Original: %d bytes, Retrieved: %d bytes, Size(): %d",
			len(testData), len(mockContent), mockSize)
		t.Logf("Mock - Original content: %q", string(testData))
		t.Logf("Mock - Retrieved content: %q", string(mockContent))

		// Test with real IPFS if available
		if os.Getenv("IPFS_API_PATH") != "" {
			realClient := setupRealClient(t)

			// Upload to real IPFS
			realFile := NewIPFSFileFromBytes(testData)
			realPath, err := realClient.Unixfs().Add(context.Background(), realFile)
			require.NoError(t, err)

			// Retrieve from real IPFS
			realNode, err := realClient.Unixfs().Get(context.Background(), realPath)
			require.NoError(t, err)
			defer realNode.Close()

			realContent, err := io.ReadAll(realNode)
			require.NoError(t, err)

			realSize, err := realNode.Size()
			require.NoError(t, err)

			t.Logf("Real - Original: %d bytes, Retrieved: %d bytes, Size(): %d",
				len(testData), len(realContent), realSize)
			t.Logf("Real - Original content: %q", string(testData))
			t.Logf("Real - Retrieved content: %q", string(realContent))

			// Compare behaviors - both should work correctly now
			tassert.Equal(t, testData, realContent, "Real IPFS should return original content")
			tassert.Equal(t, testData, mockContent, "Mock IPFS should return original content (FIXED)")

			// Size handling - mock provides size, real IPFS might not (due to no Content-Length header)
			tassert.Equal(t, int64(len(testData)), mockSize, "Mock IPFS should provide correct size (FIXED)")
			// Real IPFS size might be -1 if Content-Length header is not provided
			if realSize != -1 {
				tassert.Equal(t, int64(len(testData)), realSize, "Real IPFS size should match when available")
			} else {
				t.Logf("Real IPFS doesn't provide Content-Length, size is unknown (-1)")
			}
		}
	})
}

func TestIPFSHandlerBehaviorComparison(t *testing.T) {
	testData := []byte("handler test content")

	t.Run("ipfsCatHandlerWithClient - Mock vs Real", func(t *testing.T) {
		mockClient := setupMockClient(t)

		// Upload to mock
		mockFile := NewIPFSFileFromBytes(testData)
		mockPath, err := mockClient.Unixfs().Add(context.Background(), mockFile)
		require.NoError(t, err)
		mockCID := mockPath.String()

		// Test handler with mock client
		mockHandler := ipfsCatHandlerWithClient(mockClient)
		mockReq := httptest.NewRequest("GET", "/ipfs/"+mockCID, nil)
		mockW := httptest.NewRecorder()
		mockHandler(mockW, mockReq)

		t.Logf("Mock Handler - Status: %d", mockW.Code)
		t.Logf("Mock Handler - Content-Length: %s", mockW.Header().Get("Content-Length"))
		t.Logf("Mock Handler - Body length: %d", len(mockW.Body.Bytes()))
		t.Logf("Mock Handler - Body content: %q", mockW.Body.String())

		if os.Getenv("IPFS_API_PATH") != "" {
			realClient := setupRealClient(t)

			// Upload to real IPFS
			realFile := NewIPFSFileFromBytes(testData)
			realPath, err := realClient.Unixfs().Add(context.Background(), realFile)
			require.NoError(t, err)
			realCID := realPath.String()

			// Test handler with real client
			realHandler := ipfsCatHandlerWithClient(realClient)
			realReq := httptest.NewRequest("GET", "/ipfs/"+realCID, nil)
			realW := httptest.NewRecorder()
			realHandler(realW, realReq)

			t.Logf("Real Handler - Status: %d", realW.Code)
			t.Logf("Real Handler - Content-Length: %s", realW.Header().Get("Content-Length"))
			t.Logf("Real Handler - Body length: %d", len(realW.Body.Bytes()))
			t.Logf("Real Handler - Body content: %q", realW.Body.String())

			// Both should now work correctly
			tassert.Equal(t, http.StatusOK, realW.Code, "Real IPFS handler should succeed")
			tassert.Equal(t, testData, realW.Body.Bytes(), "Real IPFS handler should return original content")

			tassert.Equal(t, http.StatusOK, mockW.Code, "Mock IPFS handler should succeed (FIXED)")
			tassert.Equal(t, testData, mockW.Body.Bytes(), "Mock IPFS handler should return original content (FIXED)")

			// Content-Length handling depends on whether size is available
			realContentLength := realW.Header().Get("Content-Length")
			mockContentLength := mockW.Header().Get("Content-Length")

			tassert.Equal(t, strconv.Itoa(len(testData)), mockContentLength,
				"Mock handler should set correct Content-Length (FIXED)")

			// Real IPFS might not provide Content-Length if size is unknown
			if realContentLength == "" {
				t.Logf("Real IPFS handler omitted Content-Length (size unknown)")
			} else {
				tassert.Equal(t, strconv.Itoa(len(testData)), realContentLength,
					"Real IPFS handler should set correct Content-Length when size is known")
			}
		}
	})
}

func TestIPFSSizeBugDemonstration(t *testing.T) {
	testData := []byte("size bug test")

	t.Run("IPFSNode Size() bug in mock implementation", func(t *testing.T) {
		mockClient := setupMockClient(t)

		// Upload content
		file := NewIPFSFileFromBytes(testData)
		path, err := mockClient.Unixfs().Add(context.Background(), file)
		require.NoError(t, err)

		// Get the node
		node, err := mockClient.Unixfs().Get(context.Background(), path)
		require.NoError(t, err)
		defer node.Close()

		// Check size - this should be len(testData) but will be 0 in mock
		size, err := node.Size()
		require.NoError(t, err)

		t.Logf("Original data size: %d", len(testData))
		t.Logf("IPFSNode.Size() returned: %d", size)

		// This should now be fixed
		tassert.Equal(t, int64(len(testData)), size, "Mock IPFSNode.Size() should return correct size (FIXED)")
		tassert.NotEqual(t, int64(0), size, "Size should not be 0 (old bug is fixed)")
	})
}

func TestIPFSContentMismatchBugDemonstration(t *testing.T) {
	testData := []byte("content mismatch test")

	t.Run("Mock cat endpoint returns wrong content", func(t *testing.T) {
		mockClient := setupMockClient(t)

		// Upload content
		file := NewIPFSFileFromBytes(testData)
		path, err := mockClient.Unixfs().Add(context.Background(), file)
		require.NoError(t, err)
		cid := path.String()

		// Get content back
		node, err := mockClient.Unixfs().Get(context.Background(), path)
		require.NoError(t, err)
		defer node.Close()

		retrievedContent, err := io.ReadAll(node)
		require.NoError(t, err)

		t.Logf("Original content: %q", string(testData))
		t.Logf("Retrieved content: %q", string(retrievedContent))
		t.Logf("CID: %s", cid)

		// This should now be fixed - mock returns original content
		tassert.Equal(t, testData, retrievedContent,
			"Mock should return original content (FIXED)")
		expectedBuggyContent := fmt.Sprintf("mock-content-for-%s", cid)
		tassert.NotEqual(t, expectedBuggyContent, string(retrievedContent),
			"Mock should not return old buggy generated content")
	})
}

func TestIPFSRegressionPrevention(t *testing.T) {
	// These tests ensure the specific bugs we fixed don't regress

	t.Run("Regression: Mock should return original content, not generated", func(t *testing.T) {
		mockClient := setupMockClient(t)
		testData := []byte("regression test original content")

		// Upload
		file := NewIPFSFileFromBytes(testData)
		path, err := mockClient.Unixfs().Add(context.Background(), file)
		require.NoError(t, err)

		// Retrieve
		node, err := mockClient.Unixfs().Get(context.Background(), path)
		require.NoError(t, err)
		defer node.Close()

		retrieved, err := io.ReadAll(node)
		require.NoError(t, err)

		// MUST return original content, not generated mock content
		tassert.Equal(t, testData, retrieved, "Mock must return original content (regression prevention)")
		tassert.NotEqual(t, fmt.Sprintf("mock-content-for-%s", path.String()), string(retrieved),
			"Must not return old buggy generated content")
	})

	t.Run("Regression: IPFSNode.Size() should return actual size, not 0", func(t *testing.T) {
		mockClient := setupMockClient(t)
		testData := []byte("size regression test")

		// Upload
		file := NewIPFSFileFromBytes(testData)
		path, err := mockClient.Unixfs().Add(context.Background(), file)
		require.NoError(t, err)

		// Get node
		node, err := mockClient.Unixfs().Get(context.Background(), path)
		require.NoError(t, err)
		defer node.Close()

		size, err := node.Size()
		require.NoError(t, err)

		// MUST return actual size, not 0 (the old bug)
		tassert.Equal(t, int64(len(testData)), size, "IPFSNode.Size() must return actual size (regression prevention)")
		tassert.NotEqual(t, int64(0), size, "Must not return 0 (old bug)")
	})

	t.Run("Regression: Handler should set correct Content-Length when size is known", func(t *testing.T) {
		mockClient := setupMockClient(t)
		testData := []byte("handler regression test")

		// Upload
		file := NewIPFSFileFromBytes(testData)
		path, err := mockClient.Unixfs().Add(context.Background(), file)
		require.NoError(t, err)

		// Test handler
		handler := ipfsCatHandlerWithClient(mockClient)
		req := httptest.NewRequest("GET", "/ipfs/"+path.String(), nil)
		w := httptest.NewRecorder()
		handler(w, req)

		// MUST succeed and set correct headers
		tassert.Equal(t, http.StatusOK, w.Code, "Handler must succeed")
		tassert.Equal(t, testData, w.Body.Bytes(), "Handler must return original content")
		tassert.Equal(t, strconv.Itoa(len(testData)), w.Header().Get("Content-Length"),
			"Handler must set correct Content-Length (regression prevention)")
		tassert.NotEqual(t, "0", w.Header().Get("Content-Length"), "Must not set Content-Length to 0 (old bug)")
	})

	t.Run("Regression: Handler should omit Content-Length when size is unknown", func(t *testing.T) {
		// Test that we handle unknown size correctly (don't set Content-Length to -1)
		if os.Getenv("IPFS_API_PATH") != "" {
			realClient := setupRealClient(t)
			testData := []byte("real size test")

			// Upload
			file := NewIPFSFileFromBytes(testData)
			path, err := realClient.Unixfs().Add(context.Background(), file)
			require.NoError(t, err)

			// Test handler
			handler := ipfsCatHandlerWithClient(realClient)
			req := httptest.NewRequest("GET", "/ipfs/"+path.String(), nil)
			w := httptest.NewRecorder()
			handler(w, req)

			// Should succeed
			tassert.Equal(t, http.StatusOK, w.Code, "Handler should succeed with real IPFS")
			tassert.Equal(t, testData, w.Body.Bytes(), "Handler should return original content")

			// Should either omit Content-Length or set it correctly (not to -1)
			contentLength := w.Header().Get("Content-Length")
			if contentLength != "" {
				tassert.NotEqual(t, "-1", contentLength, "Must not set Content-Length to -1 (regression prevention)")
				// If set, should be correct
				expectedLength, _ := strconv.Atoi(contentLength)
				tassert.Equal(t, len(testData), expectedLength, "If Content-Length is set, it should be correct")
			}
		}
	})
}
