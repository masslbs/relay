// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
	"github.com/ssgreg/repeat"
)

// EthLookp represents an internal ethereum operation,
// abstracted from the actual interaction with the JSON rpc
type EthLookup interface {
	getChainID() uint64
	closeWithError(error)

	// TODO: might need more context, wallet addr, key, ..?
	// KISS for now until we identified all the needed call sites
	process(*ethClient)
}

type ethRPCService struct {
	// "the control plane" where the massMarket registries are hosted
	registryChainID uint64

	// enabled ethereum chains (chainID:rpcURL)
	chains map[uint64]*ethClient

	ops chan<- EthLookup

	relayTokenID big.Int
}

// Populate the following env vars.
// See also: .env.example
//
// ETH_STORE_REGISTRY_CHAIN_ID=$n
// ETH_RPC_ENDPOINT_$n=rpcA;rpcB;rpcC
func newEthRPCService() *ethRPCService {
	r := ethRPCService{}
	r.registryChainID = uint64(mustGetEnvInt("ETH_STORE_REGISTRY_CHAIN_ID"))

	r.chains = make(map[uint64]*ethClient)
	const chainConfigEnvPrefix = "ETH_RPC_ENDPOINT_"
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, chainConfigEnvPrefix) {
			continue
		}
		values := strings.TrimPrefix(env, chainConfigEnvPrefix)
		parts := strings.SplitN(values, "=", 2)
		assert(len(parts) == 2)

		chainId, err := strconv.ParseUint(parts[0], 10, 64)
		check(err)
		var hasWebsocketEndpoint = false
		urls := strings.Split(parts[1], ";")
		for _, url := range urls {
			if strings.HasPrefix(url, "ws") {
				hasWebsocketEndpoint = true
			}
		}
		assertWithMessage(hasWebsocketEndpoint, "need at least one websocket endpoint per chain for payment subscriptions")
		r.chains[chainId] = newEthClient(chainId, urls)
	}

	ops := make(chan EthLookup)
	srv := &ethRPCService{
		ops: ops,
	}
	go srv.process(ops)

	return srv
}

func (rpc *ethRPCService) signEvent(data []byte) ([]byte, error) {
	c, has := rpc.chains[rpc.registryChainID]
	assert(has)
	return c.eventSign(data)
}

func (rpc *ethRPCService) discoveryHandleFunc(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var uint256 = make([]byte, 32)
	rpc.relayTokenID.FillBytes(uint256)
	err := json.NewEncoder(w).Encode(map[string]any{
		"relay_token_id": "0x" + hex.EncodeToString(uint256),
		"chain_id":       rpc.registryChainID,
	})
	if err != nil {
		log("ethClient.discovery err=%s", err.Error())
	}
}

func (rpc *ethRPCService) process(ops <-chan EthLookup) {
	// ctx := context.Background()
	for op := range ops {
		start := now()
		log("ethRPC.start op=%T", op)
		cid := op.getChainID()
		ethClient, ok := rpc.chains[cid]
		if !ok {
			op.closeWithError(fmt.Errorf("chain not supported: %d", cid))
			continue
		}
		// ctx, cancel := context.WithCancel(ctx)

		// TODO: re-use clientq
		//c, err := ethClient.getClient(ctx)
		//check(err) // TODO: repeat?

		op.process(ethClient)
		// cancel()
		log("ethRPC.done took=%d", took(start))
	}
}

type erc20MetadataEthLookup struct {
	chainID   uint64
	tokenAddr common.Address

	result *erc20Metadata
	errCh  chan<- error
}

func (lookup *erc20MetadataEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *erc20MetadataEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *erc20MetadataEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: context.Background(),
	}

	tokenCaller, err := NewERC20Caller(lookup.tokenAddr, rpc)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("newERC20Caller failed: %w", err))
		return

	}

	decimalCount, err := tokenCaller.Decimals(callOpts)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to get token decimals: %w", err))
		return
	}

	symbol, err := tokenCaller.Symbol(callOpts)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to get token symbol: %w", err))
		return
	}

	tokenName, err := tokenCaller.Name(callOpts)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to get token name: %w", err))
		return
	}

	lookup.result = &erc20Metadata{
		decimals:  decimalCount,
		symbol:    symbol,
		tokenName: tokenName,
	}
	return
}

type erc20Metadata struct {
	decimals  uint8
	symbol    string
	tokenName string
}

func (rpc *ethRPCService) GetERC20Metadata(chainID uint64, tokenAddr common.Address) (*erc20Metadata, error) {
	lookup := &erc20MetadataEthLookup{
		chainID:   chainID,
		tokenAddr: tokenAddr,
	}

	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return nil, err
	}
	assert(lookup.result != nil)

	return lookup.result, nil
}

type ownerOfShopEthLookup struct {
	chainID uint64
	shopID  *big.Int

	result *common.Address
	errCh  chan<- error
}

func (lookup *ownerOfShopEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *ownerOfShopEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *ownerOfShopEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: context.Background(),
	}

	// owner
	shopReg, err := NewRegShopCaller(client.contractAddresses.ShopRegistry, rpc)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to create shop registry caller: %w", err))
		return
	}

	ownerAddr, err := shopReg.OwnerOf(callOpts, lookup.shopID)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to get shop owner: %w", err))
		return
	}
	lookup.result = &ownerAddr

	return
}

func (rpc *ethRPCService) GetOwnerOfShop(shopID *big.Int) (common.Address, error) {
	lookup := &ownerOfShopEthLookup{
		chainID: rpc.registryChainID,
		shopID:  shopID,
	}

	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return common.Address{}, err
	}
	assert(lookup.result != nil)

	return *lookup.result, nil
}

type clerkHasAccessEthLookup struct {
	chainID uint64
	shopID  *big.Int
	user    common.Address

	result bool
	errCh  chan<- error
}

func (lookup *clerkHasAccessEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *clerkHasAccessEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *clerkHasAccessEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: context.Background(),
	}

	shopReg, err := NewRegShopCaller(client.contractAddresses.ShopRegistry, rpc)
	if err != nil {
		err = fmt.Errorf("failed to create shop registry caller: %w", err)
		lookup.closeWithError(err)
		return
	}

	// updateRootHash PERM is equivalent to Clerk or higher
	perm, err := shopReg.PERMUpdateRootHash(callOpts)
	if err != nil {
		err = fmt.Errorf("failed to get updateRootHash PERM: %w", err)
		lookup.closeWithError(err)
		return
	}

	has, err := shopReg.HasPermission(callOpts, lookup.shopID, lookup.user, perm)
	if err != nil {
		err = fmt.Errorf("contract call error: %w", err)
		lookup.closeWithError(err)
		return
	}

	lookup.result = has
	return
}

func (rpc *ethRPCService) ClerkHasAccess(shopID *big.Int, user common.Address) (bool, error) {
	lookup := &clerkHasAccessEthLookup{
		chainID: rpc.registryChainID,
		shopID:  shopID,
		user:    user,
	}

	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return false, err
	}

	return lookup.result, nil
}

type blockNumberEthLookup struct {
	chainID uint64
	shopID  *big.Int

	result *uint64
	errCh  chan<- error
}

func (lookup *blockNumberEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *blockNumberEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *blockNumberEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}

	result, err := rpc.BlockNumber(client.backgroundCtx)
	if err != nil {
		lookup.closeWithError(err)
		return
	}

	lookup.result = &result
}

func (rpc *ethRPCService) GetCurrentBlockNumber(chainID uint64) (uint64, error) {
	lookup := &blockNumberEthLookup{chainID: chainID}

	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return 0, err
	}
	assert(lookup.result != nil)

	return *lookup.result, nil
}

type blockByNumberEthLookup struct {
	chainID     uint64
	blockNumber *big.Int

	result *types.Block
	errCh  chan<- error
}

func (lookup *blockByNumberEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *blockByNumberEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *blockByNumberEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}

	b, err := rpc.BlockByNumber(client.backgroundCtx, lookup.blockNumber)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to get blockNum %s: %w", lookup.blockNumber, err))
		return
	}

	lookup.result = b
	return
}

func (rpc *ethRPCService) GetBlockByNumber(chainID uint64, blockNum *big.Int) (*types.Block, error) {
	lookup := &blockByNumberEthLookup{
		chainID:     chainID,
		blockNumber: blockNum,
	}
	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return nil, err
	}
	assert(lookup.result != nil)

	return lookup.result, nil
}

type paymentIDandAddressEthLookup struct {
	chainID    uint64
	paymentReq *PaymentRequest
	fallback   common.Address

	resultID   *big.Int
	resultAddr common.Address

	errCh chan<- error
}

func (lookup *paymentIDandAddressEthLookup) getChainID() uint64 { return lookup.chainID }
func (lookup *paymentIDandAddressEthLookup) closeWithError(err error) {
	lookup.errCh <- err
	close(lookup.errCh)
}

func (lookup *paymentIDandAddressEthLookup) process(client *ethClient) {
	rpc, err := client.getRPC()
	if err != nil {
		err = fmt.Errorf("failed to estrablish RPC client: %w", err)
		lookup.closeWithError(err)
		return
	}
	ctx := client.backgroundCtx

	callOpts := &bind.CallOpts{
		Pending: false,
		Context: ctx,
	}

	// get paymentId and create fallback address
	paymentsContract, err := NewPaymentsByAddressCaller(client.contractAddresses.Payments, rpc)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to instantiate contract helper: %w", err))
		return
	}

	paymentId, err := paymentsContract.GetPaymentId(callOpts, *lookup.paymentReq)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to retreive paymentID: %w", err))
		return
	}

	purchaseAddr, err := paymentsContract.GetPaymentAddress(callOpts, *lookup.paymentReq, lookup.fallback)
	if err != nil {
		lookup.closeWithError(fmt.Errorf("failed to retreive paymentAddr: %w", err))
		return
	}
	lookup.resultID = paymentId
	lookup.resultAddr = purchaseAddr

	return
}

func (rpc *ethRPCService) GetPaymentIDAndAddress(chainID uint64, pr *PaymentRequest, fallback common.Address) (*big.Int, common.Address, error) {
	lookup := &paymentIDandAddressEthLookup{
		chainID:    chainID,
		paymentReq: pr,
		fallback:   fallback,
	}
	errCh := make(chan error)
	lookup.errCh = errCh

	rpc.ops <- lookup

	if err := <-errCh; err != nil {
		return nil, common.Address{}, err
	}
	assert(lookup.resultID != nil)

	return lookup.resultID, lookup.resultAddr, nil
}

// TODO: this should be derived somehow
// - should be per store
var relayKeyCardID requestID

// single jsonrpc client instance
type ethClient struct {
	chainID uint64
	rpcUrls []string

	backgroundCtx  context.Context
	lastClient     *ethclient.Client
	lastWebsockRPC *ethclient.Client

	gasTipCap *big.Int
	gasFeeCap *big.Int

	erc20ContractABI abi.ABI

	contractAddresses struct {
		Payments      common.Address `json:"Payments"`
		ShopRegistry  common.Address `json:"ShopReg"`
		RelayRegistry common.Address `json:"RelayReg"`
	}
	secret *ecdsa.PrivateKey
	wallet common.Address

	relayTokenID *big.Int
}

//go:embed gen_contract_addresses.json
var genContractAddresses embed.FS

func newEthClient(chainID uint64, rpcURLs []string) *ethClient {
	var c ethClient
	var err error

	c.chainID = chainID
	c.rpcUrls = rpcURLs

	log("ethClient chainId=%d rpcs=%d", c.chainID, len(c.rpcUrls))

	ctx := context.Background()
	c.backgroundCtx = ctx
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	// register a new nft for the relay
	relaysReg, gethc, err := c.newRelayReg()
	check(err)

	// check rpc works
	err = repeat.Repeat(
		repeat.Fn(func() error {
			err := c.updateGasLimit(ctx, gethc)
			if errors.Is(err, context.DeadlineExceeded) {
				return repeat.HintTemporary(err)
			}
			return err
		}),
		repeat.WithDelay(repeat.FullJitterBackoff(250*time.Millisecond).Set()),
		repeat.StopOnSuccess(),
		repeat.LimitMaxTries(5),
	)
	check(err)

	// TODO: multiple keyfiles?
	if keyPath := os.Getenv("ETH_PRIVATE_KEY_FILE"); keyPath != "" {
		keyData, err := os.ReadFile(keyPath)
		check(err)
		log("ethClient.keyPairFile path=%s len=%d", keyPath, len(keyData))
		trimmed := strings.TrimSpace(string(keyData))
		c.secret, err = crypto.HexToECDSA(trimmed)
		check(err)
	} else {
		c.secret, err = crypto.HexToECDSA(mustGetEnvString("ETH_PRIVATE_KEY"))
		check(err)
	}

	publicKey := c.secret.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	assertWithMessage(ok, "Error casting public key to ECDSA")

	c.wallet = crypto.PubkeyToAddress(*publicKeyECDSA)
	log("ethClient.newEthClient wallet=%s", c.wallet.Hex())

	relayKeyCardID = make([]byte, requestIDBytes)
	copy(relayKeyCardID, c.wallet.Bytes())

	has := c.hasBalance(ctx, c.wallet)
	_ = has

	addrData, err := genContractAddresses.ReadFile("gen_contract_addresses.json")
	check(err)
	err = json.Unmarshal(addrData, &c.contractAddresses)
	check(err)

	log("ethClient.newEthClient shopRegAddr=%s", c.contractAddresses.ShopRegistry.Hex())
	log("ethClient.newEthClient relayRegAddr=%s", c.contractAddresses.RelayRegistry.Hex())
	log("ethClient.newEthClient paymentsAddr=%s", c.contractAddresses.Payments.Hex())

	c.erc20ContractABI, err = abi.JSON(strings.NewReader(ERC20MetaData.ABI))
	check(err)

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    c.wallet,
		Context: ctx,
	}

	relayTokenID := new(big.Int)
	if nftIDStr := os.Getenv("RELAY_NFT_ID"); nftIDStr != "" {
		buf, err := hex.DecodeString(nftIDStr)
		check(err)
		assertWithMessage(len(buf) == 32, fmt.Sprintf("expected 32bytes of data in RELAY_NFT_ID. got %d", len(buf)))
		relayTokenID.SetBytes(buf)

		nftOwner, err := relaysReg.OwnerOf(callOpts, relayTokenID)
		check(err)
		assertWithMessage(nftOwner.Cmp(c.wallet) == 0, fmt.Sprintf("passed NFT is owned by %s", nftOwner))

	} else { // in testing, always create a new nft
		buf := make([]byte, 32)
		rand.Read(buf)
		relayTokenID.SetBytes(buf)

		txOpts, err := c.makeTxOpts(ctx, gethc)
		check(err)
		tx, err := relaysReg.Mint(txOpts, relayTokenID, c.wallet, fmt.Sprintf("http://localhost:%d/relay_nft?token=%s", mustGetEnvInt("PORT"), relayTokenID))
		check(err)

		err = c.checkTransaction(ctx, gethc, tx)
		check(err)
	}
	gethc.Close()

	log("ethClient.relayNft token=%s", relayTokenID)
	c.relayTokenID = relayTokenID

	return &c
}

func (c *ethClient) getWebsocketRPC() (*ethclient.Client, error) {
	if last := c.lastWebsockRPC; last != nil {
		_, err := last.BlockNumber(c.backgroundCtx)
		if err == nil {
			return last, nil
		}
		c.lastWebsockRPC = nil
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		// custom dialer..?
	}

	var wsURLs []string
	for _, u := range c.rpcUrls {
		if !strings.HasPrefix(u, "ws") {
			continue
		}
		wsURLs = append(wsURLs, u)
	}

	randomIndex := mrand.Intn(len(wsURLs))
	randomRPCURL := wsURLs[randomIndex]
	debug("ethClient.getWSClient rpc=%s", randomRPCURL)

	gethRPC, err := rpc.DialOptions(c.backgroundCtx,
		randomRPCURL,
		rpc.WithWebsocketDialer(dialer),
		// TODO: with retry http roundtripper for http endpoints
		// https://pkg.go.dev/github.com/hashicorp/go-retryablehttp#Client
	)
	if err != nil {
		return nil, err
	}
	return ethclient.NewClient(gethRPC), nil
}

func (c *ethClient) getRPC() (*ethclient.Client, error) {
	if last := c.lastClient; last != nil {
		err := c.updateGasLimit(c.backgroundCtx, last)
		if err == nil {
			return last, nil
		}
		c.lastClient = nil
	}

	// TODO: retry
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
	}

	randomIndex := mrand.Intn(len(c.rpcUrls))
	randomRPCURL := c.rpcUrls[randomIndex]
	debug("ethClient.newClient chainID=%d rpc=%s", c.chainID, randomRPCURL)

	gethRPC, err := rpc.DialOptions(c.backgroundCtx,
		randomRPCURL,
		rpc.WithWebsocketDialer(dialer),
		// TODO: with retry http roundtripper for http endpoints
		// https://pkg.go.dev/github.com/hashicorp/go-retryablehttp#Client
	)
	if err != nil {
		return nil, err
	}
	newClient := ethclient.NewClient(gethRPC)
	c.lastClient = newClient
	return newClient, err
}

func (c ethClient) newRelayReg() (*RegRelay, *ethclient.Client, error) {
	client, err := c.getRPC()
	if err != nil {
		return nil, nil, err
	}
	reg, err := NewRegRelay(c.contractAddresses.RelayRegistry, client)
	if err != nil {
		return nil, nil, fmt.Errorf("ethClient.newRelayReg: creating relay registry failed: %w", err)
	}
	return reg, client, nil
}

func (c ethClient) newShopReg() (*RegShop, *ethclient.Client, error) {
	client, err := c.getRPC()
	if err != nil {
		return nil, nil, err
	}

	reg, err := NewRegShop(c.contractAddresses.ShopRegistry, client)
	if err != nil {
		return nil, nil, fmt.Errorf("ethClient.newShopReg: creating shop registry failed: %w", err)
	}

	return reg, client, nil
}

func (c ethClient) makeTxOpts(ctx context.Context, client *ethclient.Client) (*bind.TransactOpts, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.updateGasLimit(ctx, client); err != nil {
		return nil, err
	}
	return &bind.TransactOpts{
		Context:   ctx,
		From:      c.wallet,
		GasFeeCap: c.gasFeeCap,
		GasTipCap: big.NewInt(1),
		Nonce:     nil,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			return types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(int64(c.chainID))), c.secret)
		},
	}, nil
}

func (c ethClient) checkTransaction(ctx context.Context, conn *ethclient.Client, tx *types.Transaction) error {
	receipt, err := bind.WaitMined(ctx, conn, tx)
	if err != nil {
		return fmt.Errorf("waiting for mint failed: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("call failed with status: %d", receipt.Status)
	}
	return nil
}

func (c *ethClient) updateGasLimit(ctx context.Context, client *ethclient.Client) error {
	var err error
	c.gasFeeCap, err = client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("ethClient.updateGasLimit: gas price failed: %w", err)
	}
	log("ethClient.updateGasLimit gasFeeCap=%s", c.gasFeeCap)
	c.gasTipCap, err = client.SuggestGasTipCap(ctx)
	if err != nil {
		return fmt.Errorf("ethClient.updateGasLimit: gas tip cap failed: %w", err)
	}
	log("ethClient.updateGasLimit gasTipCap=%s", c.gasTipCap)
	return nil
}

func (c ethClient) hasBalance(ctx context.Context, addr common.Address) bool {
	rpc, err := c.getRPC()
	if err != nil {
		log("ethClient.hasBalance.getClient error=%s", err)
		return false
	}
	currBlock, err := rpc.BlockNumber(ctx)
	if err != nil {
		log("ethClient.hasBalance.blockNo error=%s", err)
		return false
	}
	balance, err := rpc.BalanceAt(ctx, addr, big.NewInt(int64(currBlock)))
	if err != nil {
		log("ethClient.hasBalance.balanceAt error=%s", err)
		return false
	}
	log("ethClient balance=%d wallet=%s", balance.Int64(), addr.Hex())
	return balance.Int64() > 0
}
