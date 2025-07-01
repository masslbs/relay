// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Package main implements the relay server for a massMarket shop
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5"
	cbor "github.com/masslbs/network-schema/go/cbor"
	"github.com/masslbs/network-schema/go/objects"
	"github.com/masslbs/network-schema/go/patch"
	pb "github.com/masslbs/network-schema/go/pb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/ssgreg/repeat"
)

// set via ldflags during build
var release = "unset"

// Server configuration.
const (
	sessionLastSeenAtFlushLimit   = 30 * time.Second
	sessionLastAckedSeqFlushLimit = 4096
	sessionBufferSizeRefill       = limitMaxOutRequests * limitMaxOutBatchSize
	sessionBufferSizeMax          = limitMaxOutRequests * limitMaxOutBatchSize * 2

	watcherTimeout           = 5 * time.Second
	databaseDebounceInterval = 100 * time.Millisecond
	tickStatsInterval        = 1 * time.Second
	tickBlockThreshold       = 50 * time.Millisecond
	memoryStatsInterval      = 5 * time.Second
	emitUptimeInterval       = 10 * time.Second

	databaseOpsChanSize           = 64 * 1024
	databasePropagationEventLimit = 5000

	DefaultPaymentTTL = 60 * 60 * 24
)

// Toggle high-volume log traffic.
var (
	logMessages = false
	logMetrics  = false

	sessionPingInterval   = 15 * time.Second
	sessionKickTimeout    = 3 * sessionPingInterval
	ethereumBlockInterval = 15 * time.Second
)

// Enable error'd and ignore'd requests to be simulated with env variable.
// Given in integer percents, 0 <= r <= 100.
var simulateErrorRate = 0
var simulateIgnoreRate = 0

var (
	networkVersions            = []uint{5}
	currentRelayVersion uint16 = 5
)

var initLoggingOnce sync.Once

func initLogging() {
	logMessages = mustGetEnvBool("LOG_MESSAGES")
	logMetrics = mustGetEnvBool("LOG_METRICS")

	simulateErrorRateStr := os.Getenv("SIMULATE_ERROR_RATE")
	if simulateErrorRateStr != "" {
		var err error
		simulateErrorRate, err = strconv.Atoi(simulateErrorRateStr)
		check(err)
		assert(simulateErrorRate >= 0 && simulateErrorRate <= 100)
	}

	simulateIgnoreRateStr := os.Getenv("SIMULATE_IGNORE_RATE")
	if simulateIgnoreRateStr != "" {
		var err error
		simulateIgnoreRate, err = strconv.Atoi(simulateIgnoreRateStr)
		check(err)
		assert(simulateIgnoreRate >= 0 && simulateIgnoreRate <= 100)
	}

	// optional - mostly for testing
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	optPingInterval, err := time.ParseDuration(pingIntervalStr)
	if pingIntervalStr != "" && err == nil {
		sessionPingInterval = optPingInterval
	}

	kickTimeoutStr := os.Getenv("KICK_TIMEOUT")
	optKickTimeout, err := time.ParseDuration(kickTimeoutStr)
	if kickTimeoutStr != "" && err == nil {
		sessionKickTimeout = optKickTimeout
	}

	ethereumBlockIntervalStr := os.Getenv("ETH_BLOCK_INTERVAL")
	optBlockInterval, err := time.ParseDuration(ethereumBlockIntervalStr)
	if ethereumBlockIntervalStr != "" && err == nil {
		ethereumBlockInterval = optBlockInterval
	}
}

// TODO: differentiate network-schema errors from relay errors
// func (err *Error) Error() string {
// 	return "(" + ErrorCodes_name[int32(err.Code)] + "): " + err.Message
// }

func coalesce(errs ...*pb.Error) *pb.Error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

var tooManyConcurrentRequestsError = &pb.Error{
	Code:    pb.ErrorCodes_TOO_MANY_CONCURRENT_REQUESTS,
	Message: "Too many concurrent requests sent to server",
}

var alreadyAuthenticatedError = &pb.Error{
	Code:    pb.ErrorCodes_ALREADY_AUTHENTICATED,
	Message: "Already authenticated in a previous message",
}

var notAuthenticatedError = &pb.Error{
	Code:    pb.ErrorCodes_NOT_AUTHENTICATED,
	Message: "Must authenticate before sending any other messages",
}

var alreadyConnectedError = &pb.Error{
	Code:    pb.ErrorCodes_ALREADY_CONNECTED,
	Message: "Already connected from this keyCard in another session",
}

var unlinkedKeyCardError = &pb.Error{
	Code:    pb.ErrorCodes_UNLINKED_KEYCARD,
	Message: "Key Card was removed from the Shop",
}

var notAllowedError = &pb.Error{
	Code:    pb.ErrorCodes_INVALID,
	Message: "not allowed",
}

var notFoundError = &pb.Error{
	Code:    pb.ErrorCodes_NOT_FOUND,
	Message: "Item not found",
}

var notEnoughStockError = &pb.Error{
	Code:    pb.ErrorCodes_OUT_OF_STOCK,
	Message: "not enough stock",
}

var simulateError = &pb.Error{
	Code:    pb.ErrorCodes_SIMULATED,
	Message: "Error condition simulated for this message",
}

var minimumVersionError = &pb.Error{
	Code:    pb.ErrorCodes_MINIMUM_VERSION_NOT_REACHED,
	Message: "Minimum version not reached for this request",
}

// Metric maps a name to a prometheus metric.
type Metric struct {
	mu                sync.Mutex
	name2gauge        map[string]prometheus.Gauge
	name2counter      map[string]prometheus.Counter
	httpStatusCodes   *prometheus.CounterVec
	httpResponseTimes *prometheus.GaugeVec
}

func newMetric() *Metric {
	return &Metric{
		name2gauge:   make(map[string]prometheus.Gauge),
		name2counter: make(map[string]prometheus.Counter),
		httpStatusCodes: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "http_response_codes",
		}, []string{"status", "path"}),
		httpResponseTimes: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "http_response_times",
		}, []string{"status", "path"}),
	}
}

func (m *Metric) connect() {
	log("metric.connect")

	srv := http.Server{}
	srv.Addr = mustGetEnvString("LISTENER_METRIC")
	srv.Handler = promhttp.Handler()
	err := srv.ListenAndServe()
	check(err)
}

func (m *Metric) gaugeSet(name string, value float64) {
	if logMetrics {
		log("metric.emit name=%s value=%d", name, value)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	gauge, has := m.name2gauge[name]
	if !has {
		gauge = promauto.NewGauge(prometheus.GaugeOpts{
			Name: name,
		})
	}

	gauge.Set(value)
	if !has {
		m.name2gauge[name] = gauge
	}

}

func (m *Metric) counterAdd(name string, value float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	counter, has := m.name2counter[name]
	if !has {
		counter = promauto.NewCounter(prometheus.CounterOpts{
			Name: name,
		})
	}

	counter.Add(value)
	if !has {
		m.name2counter[name] = counter
	}
}

// If PORT_PPROF is set to anything but an integer, this will silently fail.
func openPProfEndpoint() {
	var (
		port int
		err  error
	)

	if port, err = strconv.Atoi(os.Getenv("PORT_PPROF")); err != nil {
		return
	}

	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	go func() {
		listenAddr := fmt.Sprintf("localhost:%d", port)
		log("pprof addr=%s", listenAddr)
		err := http.ListenAndServe(listenAddr, pprofMux)
		check(err)
	}()
}

func emitUptime(metric *Metric) {
	start := now()
	for {
		uptime := time.Since(start).Milliseconds()
		log("relay.emitUptime uptime=%v", uptime)
		metric.gaugeSet("server_uptime", float64(uptime))
		time.Sleep(emitUptimeInterval)
	}
}

func server() {
	initLoggingOnce.Do(initLogging)
	port := mustGetEnvInt("PORT")
	log("relay.start version=%s port=%d logMessages=%t simulateErrorRate=%d simulateIgnoreRate=%d sessionPingInterval=%s, sessionKickTimeout=%s",
		release, port, logMessages, simulateErrorRate, simulateIgnoreRate, sessionPingInterval, sessionKickTimeout)

	metric := newMetric()

	r := newRelay(metric)
	r.connect()
	r.writesEnabled = true
	go r.run()

	// spawn on-chain watchers

	type watcher struct {
		name string
		fn   func(*ethClient) error
	}
	var (
		fns = []watcher{
			{"paymentMade", r.subscribeFilterLogsPaymentsMade},
			{"erc20", r.subscribeFilterLogsERC20Transfers},
			{"vanilla-eth", r.subscribeNewHeadsForEther},
		}
	)

	delay := repeat.FullJitterBackoff(250 * time.Millisecond)
	delay.MaxDelay = ethereumBlockInterval

	// onchain accounts only need to happen on the chain where the shop registry contract is hosted
	go func() {
		defer sentryRecover()
		chainID := r.ethereum.registryChainID
		geth, has := r.ethereum.chains[chainID]
		assert(has)

		countError := repeat.FnOnError(repeat.FnES(func(err error) {
			log("watcher.error name=onchain-accounts chainId=%d err=%s", chainID, err)
			r.metric.counterAdd("relay_watchError_error", 1)
		}))

		err := repeat.Repeat(
			repeat.Fn(func() error {
				return r.subscribeAccountEvents(geth)
			}),
			repeat.WithDelay(delay.Set()),
			countError,
		)
		panic(err) // TODO: panic reporting
	}()

	for _, geth := range r.ethereum.chains {
		for _, w := range fns {
			go func(w watcher, c *ethClient) {
				defer sentryRecover()
				log("watcher.spawned name=%s chainId=%d", w.name, c.chainID)

				countError := repeat.FnOnError(repeat.FnES(func(err error) {
					log("watcher.error name=%s chainId=%d err=%s", w.name, c.chainID, err)
					r.metric.counterAdd("relay_watchError_error", 1)
				}))
				waitForNextBlock := repeat.FnOnSuccess(repeat.FnS(func() {
					log("watcher.success name=%s chainId=%d", w.name, c.chainID)
				}))
				err := repeat.Repeat(
					repeat.Fn(func() error { return w.fn(c) }),
					waitForNextBlock,
					countError,
					repeat.WithDelay(delay.Set()),
				)
				panic(err) // TODO: panic reporting
			}(w, geth)
		}
	}

	// open metrics and pprof after relay & ethclient booted
	openPProfEndpoint()
	go metric.connect()

	go emitUptime(metric)

	mux := http.NewServeMux()

	// Public APIs
	for _, v := range networkVersions {
		mux.HandleFunc(fmt.Sprintf("/v%d/sessions", v), sessionsHandleFunc(v, r))
		mux.HandleFunc(fmt.Sprintf("/v%d/enroll_key_card", v), enrollKeyCardHandleFunc(v, r))

		mux.HandleFunc(fmt.Sprintf("/v%d/upload_blob", v), uploadBlobHandleFunc(v, r))
	}

	// Internal engineering APIs
	mux.HandleFunc("/health", healthHandleFunc(r))
	mux.HandleFunc("/sentry-test", sentryTestHandler())

	// Reliability Kludge
	// by serving our own ipfs repository we ensure the blobs we added are immediately available
	mux.HandleFunc("/ipfs/", ipfsCatHandleFunc())

	corsOpts := cors.Options{
		AllowedOrigins: []string{"*"},
	}
	if isDevEnv {
		mux.HandleFunc("/testing/discovery", r.ethereum.discoveryHandleFunc)
		corsOpts.Debug = true
	}

	wrappedHandler := sentrySetupHTTPHandler(mux)

	// Flush buffered events before the program terminates.
	// Set the timeout to the maximum duration the program can afford to wait.
	defer sentry.Flush(sentryFlushTimeout)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: cors.New(corsOpts).Handler(wrappedHandler),
	}
	err := srv.ListenAndServe()
	check(err)
}

// CLI

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  relay server\n")
	fmt.Fprintf(os.Stderr, "  relay dump-shop <shop-id> <output-file>\n")
	fmt.Fprintf(os.Stderr, "  relay cbor-decode <type> <cbor-data>\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cmd := os.Args[1]
	cmdArgs := os.Args[2:]
	if cmd == "server" && len(cmdArgs) == 0 {
		// need clean shutdown for coverage reports
		// TODO: move this into server()... maybe?
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range signalChan {
				fmt.Printf("\nReceived signal: %s. Initiating shutdown...\n", sig)
				os.Exit(0)
			}
		}()
		server()
	} else if cmd == "dump-shop" {
		if len(cmdArgs) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: relay dump-shop <shop-id> <output-file>\n")
			os.Exit(1)
		}
		shopID := strings.TrimPrefix(cmdArgs[0], "0x")
		outputFile := cmdArgs[1]
		var output io.Writer
		if outputFile == "-" {
			output = os.Stdout
		} else {
			var err error
			output, err = os.Create(outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create output file: %s\n", err)
				os.Exit(1)
			}
		}
		err := dumpShop(shopID, output)
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			os.Exit(1)
		}
	} else if cmd == "cbor-decode" {
		if len(cmdArgs) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: relay cbor-decode <type> <cbor-data>\n")
			os.Exit(1)
		}
		cborData, err := hex.DecodeString(cmdArgs[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode hex: %s\n", err)
			os.Exit(1)
		}
		switch cmdArgs[0] {
		case "Patch":
			var patch patch.Patch
			err := cbor.Unmarshal([]byte(cborData), &patch)
			check(err)
			spew.Dump(patch)
		case "manifest":
			var manifest objects.Manifest
			err := cbor.Unmarshal([]byte(cborData), &manifest)
			check(err)
			spew.Dump(manifest)
		default:
			fmt.Fprintf(os.Stderr, "Unhandled type: %s\n", cmdArgs[0])
			os.Exit(1)
		}
	} else {
		usage()
	}
}

func dumpShop(tokenIDHex string, output io.Writer) error {
	tokenIDBytes, err := hex.DecodeString(tokenIDHex)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %s", err)
	}
	if len(tokenIDBytes) > 32 {
		return fmt.Errorf("shop ID must be 32 bytes")
	}
	bigTokenID := big.NewInt(0).SetBytes(tokenIDBytes)

	r := newRelay(nil)
	r.connect()

	var (
		dbID   uint64
		shopID ObjectIDArray
		ctx    = context.Background()
	)

	err = r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, bigTokenID.String()).Scan(&dbID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("shop not found (tokenId=%s)", bigTokenID)
		}
		return fmt.Errorf("failed to retrieve shop: %s", err)
	}
	binary.BigEndian.PutUint64(shopID[:], dbID)

	r.hydrateShops(NewSetInts(shopID))
	shopState, ok := r.shopIDsToShopState.GetHas(shopID)
	if !ok {
		return fmt.Errorf("shop not found")
	}

	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Shop ID:\t%s\n", shopID)
	fmt.Fprintf(w, "Shop Token ID (base 10):\t%s\n", shopState.data.Manifest.ShopID.String())

	rootHash, err := shopState.data.Hash()
	if err != nil {
		return fmt.Errorf("failed to get shop root hash: %s", err)
	}
	fmt.Fprintf(w, "Shop Root Hash:\t%x\n", rootHash)
	fmt.Fprintf(w, "PatchSets:\t%d\n", shopState.lastUsedSeq)
	fmt.Fprintf(w, "Accounts:\t%d\n", shopState.data.Accounts.Size())
	fmt.Fprintf(w, "Listings:\t%d\n", shopState.data.Listings.Size())
	fmt.Fprintf(w, "Inventory:\t%d\n", shopState.data.Inventory.Size())
	fmt.Fprintf(w, "Tags:\t%d\n", shopState.data.Tags.Size())
	fmt.Fprintf(w, "Orders:\t%d\n", shopState.data.Orders.Size())
	w.Flush()

	err = cbor.DefaultEncoder(output).Encode(shopState.data)
	if err != nil {
		return fmt.Errorf("failed to encode shop: %s", err)
	}
	return nil
}
