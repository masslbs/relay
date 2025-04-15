// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/ipfs/boxo/path"
)

var pinataJWT string

var pinataReadTokenOnce sync.Once

func pinataReadToken() {
	tokBytes, err := os.ReadFile(mustGetEnvString("PINATA_JWT_FILE"))
	check(err)
	pinataJWT = strings.TrimSpace(string(tokBytes))
}

type pinataPinResponse struct {
	ID     string `json:"id"`
	CID    string `json:"ipfsHash"`
	Status string `json:"status"`
	Name   string `json:"name"`
}

func pinataPin(cid path.ImmutablePath, name string) (pinataPinResponse, error) {
	pinataReadTokenOnce.Do(pinataReadToken)

	host := mustGetEnvString("PINATA_API_HOST")
	url := fmt.Sprintf("https://%s/pinning/pinByHash", host)

	// Create the request body
	requestBody := map[string]any{
		"hashToPin": cid.RootCid().String(),
		"pinataMetadata": map[string]string{
			"name": name,
		},
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return pinataPinResponse{}, fmt.Errorf("pinataPin(): failed to create JSON body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return pinataPinResponse{}, fmt.Errorf("pinataPin(): failed to create the request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pinataJWT)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return pinataPinResponse{}, fmt.Errorf("pinataPin(): failed to send the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return pinataPinResponse{}, fmt.Errorf("pinataPin(): server returned status %d: body: %q", resp.StatusCode, string(body))
	}

	var response pinataPinResponse

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return pinataPinResponse{}, fmt.Errorf("pinataPin(): failed to decode response: %w", err)
	}

	return response, nil
}
