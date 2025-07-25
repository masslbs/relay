//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"context"
	"log"
)

func main() {
	log.Println("Testing IPFS replacement...")

	// Test 1: Create lightweight client
	client, err := NewLightweightIPFSClient("/ip4/127.0.0.1/tcp/5001")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Test 2: Add data
	testData := []byte("Hello, lightweight IPFS!")
	file := NewIPFSFileFromBytes(testData)

	ctx := context.Background()
	cid, err := client.Unixfs().Add(ctx, file)
	if err != nil {
		log.Fatalf("Failed to add data: %v", err)
	}

	log.Printf("Added data with CID: %s", cid.String())

	// Test 3: Get data
	node, err := client.Unixfs().Get(ctx, cid)
	if err != nil {
		log.Fatalf("Failed to get data: %v", err)
	}
	defer node.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(node)
	if err != nil {
		log.Fatalf("Failed to read data: %v", err)
	}

	if string(buf.Bytes()) != string(testData) {
		log.Fatalf("Data mismatch: expected %s, got %s", testData, buf.Bytes())
	}

	log.Println("Data retrieved successfully!")

	// Test 4: Swarm peers
	peers, err := client.Swarm().Peers(ctx)
	if err != nil {
		log.Printf("Warning: Failed to get peers: %v", err)
	} else {
		log.Printf("Found %d peers", len(peers))
	}

	log.Println("All tests passed!")
}
