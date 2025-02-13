// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gobwas/ws"
	cbor "github.com/masslbs/network-schema/go/cbor"
	"github.com/spruceid/siwe-go"
)

// HTTP Handlers

func sessionsHandleFunc(version uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	log("relay.sessionsHandleFunc version=%d", version)
	return func(w http.ResponseWriter, req *http.Request) {
		if !r.connectionLimiter.Allow() {
			http.Error(w, "Too many connection attempts", http.StatusTooManyRequests)
			r.metric.httpStatusCodes.WithLabelValues("429", req.URL.Path).Inc()
			return
		}

		if r.connectionCount.Load() >= r.maxConnections {
			http.Error(w, "Maximum connections reached", http.StatusServiceUnavailable)
			r.metric.httpStatusCodes.WithLabelValues("503", req.URL.Path).Inc()
			return
		}

		conn, _, _, err := ws.UpgradeHTTP(req, w)
		if err != nil {
			code := http.StatusInternalServerError
			if rej, ok := err.(*ws.ConnectionRejectedError); ok {
				code = rej.StatusCode()
			}
			r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
			log("relay.upgradeError %+v", err)
			return
		}

		r.connectionCount.Add(1)

		// bit of a misnomer, to set 201, but let's log it at least
		r.metric.httpStatusCodes.WithLabelValues("201", req.URL.Path).Inc()
		sess := newSession(version, conn, r.ops, r.metric)
		startOp := &StartOp{sessionID: sess.id, sessionVersion: version, sessionOps: sess.ops}
		sess.sendDatabaseOp(startOp)
		sess.run()
		r.connectionCount.Add(-1)

	}
}

// once a user is registered, they need to sign their keycard
func enrollKeyCardHandleFunc(_ uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	type requestData struct {
		Message   string `json:"message"`
		Signature []byte `json:"signature"`
	}

	fn := func(w http.ResponseWriter, req *http.Request) (int, error) {
		var data requestData
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid json: %w", err)
		}

		recoveredPubKey, err := ecrecoverEIP191([]byte(data.Message), data.Signature)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid signature: %w", err)
		}

		recoveredECDSAPubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("unmarshalPubkey failed: %w", err)
		}
		userWallet := crypto.PubkeyToAddress(*recoveredECDSAPubKey)

		msg, err := siwe.ParseMessage(data.Message)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid ERC-4361 message: %w", err)
		}

		referer := req.Referer()
		if referer != "" {
			// website logging into the relay as a remote service
			refererURL, err := url.Parse(referer)
			if err != nil {
				return http.StatusBadRequest, fmt.Errorf("bad referer")
			}

			// assuming the enrollment is directly on the relay
			if msg.GetDomain() != refererURL.Host {
				return http.StatusBadRequest, fmt.Errorf("referered domain did not match")
			}

			siweURI := msg.GetURI()
			if siweURI.Host != refererURL.Host {
				return http.StatusBadRequest, fmt.Errorf("refered URI did not match")
			}

			/* TODO: not sure how to scope this
			if siweURI.Path != req.URL.Path {
				return http.StatusBadRequest, fmt.Errorf("URI path did not match")
			}
			*/

		} else {
			// assuming the enrollment is directly on the relay, without a website involved
			if msg.GetDomain() != r.baseURL.Host {
				return http.StatusBadRequest, fmt.Errorf("domain did not match")
			}

			siweURI := msg.GetURI()
			if siweURI.Host != r.baseURL.Host {
				return http.StatusBadRequest, fmt.Errorf("domain did not match")
			}

			if siweURI.Path != req.URL.Path {
				return http.StatusBadRequest, fmt.Errorf("URI path did not match")
			}
		}

		if userWallet.Cmp(msg.GetAddress()) != 0 {
			return http.StatusBadRequest, fmt.Errorf("recovered and supplied address dont match")
		}

		if msg.GetNonce() != "00000000" {
			return http.StatusBadRequest, fmt.Errorf("invalid nonce")
		}

		resources := msg.GetResources()
		if n := len(resources); n != 3 {
			return http.StatusBadRequest, fmt.Errorf("expected 3 resources but got %d", n)
		}

		resRelayID := resources[0]
		if resRelayID.Scheme != "mass-relayid" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for relayid")
		}
		var relayShopID big.Int
		_, ok := relayShopID.SetString(resRelayID.Opaque, 10)
		if !ok {
			return http.StatusBadRequest, fmt.Errorf("invalid relayID")
		}
		if relayShopID.Cmp(r.ethereum.relayTokenID) != 0 {
			return http.StatusBadRequest, fmt.Errorf("request is not for this relay")
		}

		resShopID := resources[1]
		if resShopID.Scheme != "mass-shopid" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for shopid")
		}
		var shopTokenID big.Int
		_, ok = shopTokenID.SetString(resShopID.Opaque, 10)
		if !ok {
			return http.StatusBadRequest, fmt.Errorf("invalid shopID")
		}

		resKeyCard := resources[2]
		if resKeyCard.Scheme != "mass-keycard" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for keyCard")
		}

		keyCardStr := strings.TrimPrefix(resKeyCard.Opaque, "0x")
		keyCardPublicKey, err := hex.DecodeString(keyCardStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid hex encoding of keycard: %w", err)
		}

		if n := len(keyCardPublicKey); n != 64 {
			return http.StatusBadRequest, fmt.Errorf("keyCardPublicKey length is not 64 but %d", n)
		}

		//  check if shop exists
		_, err = r.ethereum.GetOwnerOfShop(&shopTokenID)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("no owner for shop: %w", err)
		}

		var isGuest bool = req.URL.Query().Get("guest") == "1"
		if !isGuest {
			has, err := r.ethereum.ClerkHasAccess(&shopTokenID, userWallet)
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("contract call error: %w", err)
			}
			log("relay.enrollKeyCard.verifyAccess shopTokenID=%s userWallet=%s has=%v", shopTokenID.String(), userWallet.Hex(), has)
			if !has {
				return http.StatusForbidden, errors.New("access denied")
			}
		}

		op := &KeyCardEnrolledInternalOp{
			shopNFT:          shopTokenID,
			keyCardIsGuest:   isGuest,
			keyCardPublicKey: cbor.PublicKey(keyCardPublicKey),
			userWallet:       cbor.EthereumAddress(userWallet),
			done:             make(chan error),
		}
		r.opsInternal <- op
		if err := <-op.done; err != nil {
			return http.StatusConflict, err
		}

		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(map[string]any{"success": true})
		if err != nil {
			log("relay.enrollKeyCard.responseFailure err=%s", err)
			// returning an error would mean sending error code
			// we already sent one so we cant
			return 0, nil
		}

		return http.StatusCreated, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Set(tookF(start))
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.enrollKeyCard.failed err=%s", err)
			w.WriteHeader(code)
			err = jsonEnc.Encode(map[string]any{"handler": "enrollKeyCard", "error": err.Error()})
			if err != nil {
				log("relay.enrollKeyCard.failedToRespond err=%s", err)
			}
			return
		}
	}
}

func healthHandleFunc(r *Relay) func(http.ResponseWriter, *http.Request) {
	log("relay.healthHandleFunc")
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		log("relay.health.start")
		ctx := context.Background()

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var res int
		err := r.connPool.QueryRow(ctx, `select 1`).Scan(&res)
		if err != nil {
			log("relay.health.dbs.fail err=%s", err)
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "database unavailable")
			return
		}
		// log("relay.health.dbs.pass")

		timeout := time.After(5 * time.Second)
		wait, op := NewEventLoopPing()

		select {
		case r.opsInternal <- op:
			// pass
		case <-timeout:
			log("relay.health.evtLoop.txFail")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "event loop unavailable")
			return
		}
		// log("relay.health.evtLoop.txPass")

		select {
		case <-timeout:
			log("relay.health.evtLoop.rxTimeout")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "event loop unavailable")
			return
		case <-wait:
		}

		_, _ = fmt.Fprintln(w, "health OK")
		r.metric.httpStatusCodes.WithLabelValues("200", req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues("200", req.URL.Path).Set(tookF(start))
		log("relay.health.pass took=%d", took(start))
	}
}
