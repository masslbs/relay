// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	ipfsFiles "github.com/ipfs/boxo/files"
	ipfsPath "github.com/ipfs/boxo/path"
	ipfsRpc "github.com/ipfs/kubo/client/rpc"
	"github.com/miolini/datacounter"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

// IPFS integration
const ipfsMaxConnectTries = 3

// getIpfsClient recursivly calls itself until it was able to connect or until ipfsMaxConnectTries is reached.
func getIpfsClient(ctx context.Context, errCount int, lastErr error) (*ipfsRpc.HttpApi, error) {
	if errCount >= ipfsMaxConnectTries {
		return nil, fmt.Errorf("getIpfsClient: tried %d times.. last error: %w", errCount, lastErr)
	}
	if errCount > 0 {
		log("getIpfsClient.retrying lastErr=%s", lastErr)
		// TODO: exp backoff
		time.Sleep(1 * time.Second)
	}
	ipfsAPIAddr, err := multiaddr.NewMultiaddr(mustGetEnvString("IPFS_API_PATH"))
	if err != nil {
		// TODO: check type of error
		return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: multiaddr.NewMultiaddr failed with %w", err))
	}
	ipfsClient, err := ipfsRpc.NewApi(ipfsAPIAddr)
	if err != nil {
		// TODO: check type of error
		return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: ipfsRpc.NewApi failed with %w", err))
	}
	// check connectivity
	if isDevEnv {
		_, err := ipfsClient.Unixfs().Add(ctx, ipfsFiles.NewBytesFile([]byte("test")))
		if err != nil {
			return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: (dev env) add 'test' failed %w", err))
		}
	} else {
		peers, err := ipfsClient.Swarm().Peers(ctx)
		if err != nil {
			// TODO: check type of error
			return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: ipfsClient.Swarm.Peers failed with %w", err))
		}
		if len(peers) == 0 {
			// TODO: dial another peer
			// return getIpfsClient(ctx, errCount+1, fmt.Errorf("ipfs node has no peers"))
			log("getIpfsClient.warning: no peers")
		}
	}
	return ipfsClient, nil
}

func uploadBlobHandleFunc(_ uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	fn := func(w http.ResponseWriter, req *http.Request) (int, error) {
		err := req.ParseMultipartForm(32 << 20) // 32mb max file size
		if err != nil {
			return http.StatusBadRequest, err
		}
		params := req.URL.Query()

		r.blobUploadTokensMu.Lock()
		token := params.Get("token")
		_, has := r.blobUploadTokens[token]
		if !has {
			r.blobUploadTokensMu.Unlock()
			return http.StatusBadRequest, fmt.Errorf("blobs: no such token %q", token)
		}
		delete(r.blobUploadTokens, token)
		r.blobUploadTokensMu.Unlock()

		file, _, err := req.FormFile("file")
		if err != nil {
			return http.StatusBadRequest, err
		}

		ipfsClient, err := getIpfsClient(req.Context(), 0, nil)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		dc := datacounter.NewReaderCounter(file)
		uploadHandle := ipfsFiles.NewReaderFile(dc)

		uploadedCid, err := ipfsClient.Unixfs().Add(req.Context(), uploadHandle)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		log("relay.blobUpload bytes=%d path=%s", dc.Count(), uploadedCid)
		r.metric.counterAdd("blob_upload", 1)
		r.metric.counterAdd("blob_uploadBytes", float64(dc.Count()))

		if !isDevEnv {
			go func() {
				// TODO: better pin name
				startPin := now()
				pinResp, err := pinataPin(uploadedCid, "relay-blob")
				if err != nil {
					log("relay.blobUpload.pinata err=%s", err)
					r.metric.counterAdd("blob_pinata_error", 1)
					return
				}
				log("relay.blobUpload.pinata ipfs_cid=%s pinata_id=%s status=%s", uploadedCid, pinResp.ID, pinResp.Status)
				r.metric.counterAdd("blob_pinata", 1)
				r.metric.counterAdd("blob_pinata_took", float64(took(startPin)))
			}()
		}

		var dlURL = *r.baseURL
		dlURL.Path = uploadedCid.String()

		const status = http.StatusCreated
		w.WriteHeader(status)
		err = json.NewEncoder(w).Encode(map[string]any{"ipfs_path": dlURL.Path, "url": dlURL.String()})
		if err != nil {
			log("relay.blobUpload.writeFailed err=%s", err)
			// returning nil since responding with an error is not possible at this point
		}
		return status, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Set(tookF(start))
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.blobUploadHandler err=%s", err)
			w.WriteHeader(code)
			err = jsonEnc.Encode(map[string]any{"handler": "getBlobUpload", "error": err.Error()})
			if err != nil {
				log("relay.blobUpload.writeFailed err=%s", err)
			}
			return
		}
	}
}

func ipfsCatHandleFunc() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		client, err := getIpfsClient(ctx, 0, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ipfsPath, err := ipfsPath.NewPath(req.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		node, err := client.Unixfs().Get(ctx, ipfsPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sz, err := node.Size()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f, ok := node.(ipfsFiles.File)
		if !ok {
			http.Error(w, "Not a file", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(int(sz)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	}
}

type savedItem struct {
	cid       combinedID
	versioned ipfsPath.ImmutablePath
}

type listingSnapshotter struct {
	errgroup.Group

	metric *Metric
	client *ipfsRpc.HttpApi
	shopID shopID
	items  chan<- savedItem
}

func newListingSnapshotter(m *Metric, shopID shopID) (*listingSnapshotter, <-chan savedItem, error) {
	ctx := context.Background()
	c, err := getIpfsClient(ctx, 0, nil)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan savedItem)
	return &listingSnapshotter{
		metric: m,
		client: c,
		shopID: shopID,
		items:  ch,
	}, ch, nil
}

// worker to save an listing to ipfs an pin it
// TODO: we are saving the hole listing each call, irrespective of variations, etc.
// we know the variations from the order, so it's okay but we should be able to de-duplicate it
func (ls *listingSnapshotter) save(cid combinedID, item *CachedListing) {
	ctx := context.Background()
	ls.Go(func() error {
		data, err := proto.Marshal(item.value)
		if err != nil {
			return fmt.Errorf("mkSnapshot.encodeError item_id=%d err=%s", item.value.Id, err)
		}

		uploadHandle := ipfsFiles.NewReaderFile(bytes.NewReader(data))

		uploadedCid, err := ls.client.Unixfs().Add(ctx, uploadHandle)
		if err != nil {
			return fmt.Errorf("mkSnapshot.ipfsAddError item=%d err=%s", item.value.Id, err)
		}

		// TODO: wait with pinning until after the item was sold..?
		pinKey := fmt.Sprintf("shop-%d-item-%d-%d", ls.shopID, item.value.Id, item.shopSeq)
		if !isDevEnv {
			_, err = pinataPin(uploadedCid, pinKey)
			if err != nil {
				return fmt.Errorf("mkSnapshot.pinataFail item=%d err=%s", item.value.Id, err)
			}
		}

		ls.items <- savedItem{cid, uploadedCid}

		log("relay.mkSnapshot item=%s bytes=%d path=%s", pinKey, len(data), uploadedCid)
		ls.metric.counterAdd("listing_snapshot", 1)
		ls.metric.counterAdd("listing_snapshotBytes", float64(len(data)))
		return nil
	})
}

func (ls *listingSnapshotter) Wait() error {
	err := ls.Group.Wait()
	if err != nil {
		return err
	}
	close(ls.items) // savers are done
	return nil
}
