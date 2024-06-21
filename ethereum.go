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

	"github.com/davecgh/go-spew/spew"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v4"
	"github.com/ssgreg/repeat"
)

var relayKeyCardID requestID

type ethClient struct {
	chainID uint64
	rpcUrls []string

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
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	// check rpc works
	err = repeat.Repeat(
		repeat.Fn(func() error {
			err := c.updateGasLimit(ctx)
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

	// register a new nft for the relay
	relaysReg, gethc, err := c.newRelayReg(ctx)
	check(err)

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

		txOpts, err := c.makeTxOpts(ctx)
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

func (c ethClient) getWSClient(ctx context.Context) (*ethclient.Client, error) {
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

	gethRPC, err := rpc.DialOptions(ctx,
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

func (c ethClient) getClient(ctx context.Context) (*ethclient.Client, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 1 * time.Second,
		// custom dialer..?
	}

	randomIndex := mrand.Intn(len(c.rpcUrls))
	randomRPCURL := c.rpcUrls[randomIndex]
	debug("ethClient.getClient rpc=%s", randomRPCURL)

	gethRPC, err := rpc.DialOptions(ctx,
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

func (c ethClient) newRelayReg(ctx context.Context) (*RegRelay, *ethclient.Client, error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, nil, err
	}
	reg, err := NewRegRelay(c.contractAddresses.RelayRegistry, client)
	if err != nil {
		return nil, nil, fmt.Errorf("ethClient.newRelayReg: creating relay registry failed: %w", err)
	}
	return reg, client, nil
}

func (c ethClient) newShopReg(ctx context.Context) (*RegShop, *ethclient.Client, error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, nil, err
	}

	reg, err := NewRegShop(c.contractAddresses.ShopRegistry, client)
	if err != nil {
		return nil, nil, fmt.Errorf("ethClient.newShopReg: creating shop registry failed: %w", err)
	}

	return reg, client, nil
}

func (c ethClient) makeTxOpts(ctx context.Context) (*bind.TransactOpts, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.updateGasLimit(ctx); err != nil {
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

func (c *ethClient) updateGasLimit(ctx context.Context) error {
	client, err := c.getClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

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
	client, err := c.getClient(ctx)
	if err != nil {
		log("ethClient.hasBalance.getClient error=%s", err)
		return false
	}
	defer client.Close()

	currBlock, err := client.BlockNumber(ctx)
	if err != nil {
		log("ethClient.hasBalance.blockNo error=%s", err)
		return false
	}

	balance, err := client.BalanceAt(ctx, addr, big.NewInt(int64(currBlock)))
	if err != nil {
		log("ethClient.hasBalance.balanceAt error=%s", err)
		return false
	}
	log("ethClient balance=%d wallet=%s", balance.Int64(), addr.Hex())

	return balance.Int64() > 0
}

func (c ethClient) discoveryHandleFunc(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var uint256 = make([]byte, 32)
	c.relayTokenID.FillBytes(uint256)
	err := json.NewEncoder(w).Encode(map[string]any{
		"relay_token_id": "0x" + hex.EncodeToString(uint256),
		"chain_id":       c.chainID,
	})
	if err != nil {
		log("ethClient.discovery err=%s", err.Error())
	}
}

// PaymentWaiter is a struct that holds the state of a order that is waiting for payment.
type PaymentWaiter struct {
	waiterID         requestID
	orderID          eventID
	orderFinalizedAt time.Time
	purchaseAddr     common.Address
	lastBlockNo      SQLStringBigInt
	coinsPayed       SQLStringBigInt
	coinsTotal       SQLStringBigInt
	paymentId        SQLStringBigInt

	// (optional) contract of the erc20 that we are looking for
	erc20TokenAddr *common.Address

	// set if order was payed
	orderPayedAt *time.Time
	orderPayedTx *common.Hash
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func (r *Relay) subscriptPaymentsMade(geth ethClient) error {
	log("relay.subscriptPaymentsMade.start chainID=%d", geth.chainID)

	var start = now()

	ctx := context.Background()

	gethClient, err := geth.getWSClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	// Get the latest block number.
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("relay.watchPaymentMade.blockNumber err=%s", err)
	}

	qry := ethereum.FilterQuery{
		Addresses: []common.Address{
			geth.contractAddresses.Payments,
		},
		Topics: [][]common.Hash{
			{eventSignaturePaymentMade},
		},
	}

	ch := make(chan types.Log)
	subscription, err := gethClient.SubscribeFilterLogs(ctx, qry, ch)
	if err != nil {
		return fmt.Errorf("relay.subscriptPaymentsMade.ethSubscribeFailed err=%s", err)
	}
	defer subscription.Unsubscribe()
	errch := subscription.Err()
	i := 0

	log("relay.subscriptPaymentsMade.startingBlockNo  current=%d", currentBlockNoInt)

watch:
	for {
		select {
		case err := <-errch:
			log("relay.subscriptPaymentsMade.subscriptionBroke err=%s", err)
			break watch
		case vLog := <-ch:
			debug("relay.subscriptPaymentsMade.newLog i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			spew.Dump(vLog)
			i++

			var paymentIdHash = vLog.Topics[1]

			var waiter PaymentWaiter
			openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt
FROM payments
WHERE
orderPayedAt IS NULL
AND orderFinalizedAt >= NOW() - INTERVAL '1 day'
AND paymentId = $1`
			err := r.connPool.QueryRow(ctx, openPaymentsQry, paymentIdHash.Bytes()).Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt)
			if err == pgx.ErrNoRows {
				continue
			} else if err != nil {
				check(err)
			}

			orderID := waiter.orderID
			log("relay.subscriptPaymentsMade.found orderId=%s txHash=%x", orderID, vLog.TxHash)

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			op := PaymentFoundInternalOp{
				orderID: orderID,
				txHash:  vLog.TxHash,
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			log("relay.subscriptPaymentsMade.completed cartId=%s txHash=%x", orderID, vLog.TxHash)
		}
	}

	log("relay.subscriptPaymentsMade.exited took=%d", took(start))
	return nil
}

func (r *Relay) watchEthereumPayments(ethClient ethClient) error {
	debug("relay.watchEthereumPayments.start chainID=%d", ethClient.chainID)

	var (
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Address]PaymentWaiter)
	)
	ctx, cancel := context.WithCancel(r.ethPaymentsContext)
	defer cancel()

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal
	FROM payments
	WHERE orderPayedAt IS NULL
		AND erc20TokenAddr IS NULL -- see watchErc20Payments()
		AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal)
		check(err)

		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}

		waiters[waiter.purchaseAddr] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.watchEthereumPayments.noOpenPayments took=%d", took(start))
		return nil
	}

	debug("relay.watchEthereumPayments.dbRead took=%d waiters=%d lowestLastBlock=%s", took(start), len(waiters), lowestLastBlock)

	// make geth client
	gethClient, err := ethClient.getClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	// Get the latest block number
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	check(err)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	for {
		if currentBlockNo.Cmp(lowestLastBlock) == -1 {
			// nothing to do
			debug("relay.watchEthereumPayments.noNewBlocks current=%d", currentBlockNoInt)
			break
		}
		// check each block for transactions
		block, err := gethClient.BlockByNumber(ctx, lowestLastBlock)
		if err != nil {
			return fmt.Errorf("relay.watchEthereumPayments.failedToGetBlock block=%s err=%s", lowestLastBlock, err)
		}

		for _, tx := range block.Transactions() {
			to := tx.To()
			if to == nil {
				continue // contract creation
			}
			waiter, has := waiters[*to]
			if has {
				debug("relay.watchEthereumPayments.checkTx waiter.lastBlockNo=%s checkingBlock=%s tx=%s to=%s", waiter.lastBlockNo.String(), block.Number().String(), tx.Hash().String(), tx.To().String())
				orderID := waiter.orderID
				// order, has := r.ordersByOrderID.get(orderID)
				assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

				// found a transaction to the purchase address
				// check if it's the right amount
				inTx := tx.Value()
				waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
				if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
					// it is larger or equal

					op := PaymentFoundInternalOp{
						orderID: orderID,
						txHash:  tx.Hash(),
						done:    make(chan struct{}),
					}
					r.opsInternal <- &op
					<-op.done // wait for write

					delete(waiters, waiter.purchaseAddr)
					log("relay.watchEthereumPayments.completed orderId=%s", orderID)
				} else {
					// it is still smaller
					log("relay.watchEthereumPayments.partial orderId=%s inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
					_, err := r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
					check(err) // cant recover sql errors
				}
			}
		}
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(currentBlockNo) == -1 {
				continue
			}
			// lastBlockNo += 1
			waiter.lastBlockNo.Add(&waiter.lastBlockNo.Int, bigOne)
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = lastBlockNo + 1 WHERE orderId = $1;`
			orderID := waiter.orderID
			_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, orderID)
			check(err)
			debug("relay.watchEthereumPayments.advance orderId=%x newLastBlock=%s", orderID, waiter.lastBlockNo.String())
		}
		// increment iterator
		lowestLastBlock.Add(lowestLastBlock, bigOne)
	}

	stillWaiting := len(waiters)
	debug("relay.watchEthereumPayments.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_eth_open", uint64(stillWaiting))
	return nil
}

var (
	eventSignatureTransferErc20 = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	eventSignaturePaymentMade   = crypto.Keccak256Hash([]byte("PaymentMade(uint256)"))
)

func (r *Relay) watchErc20Payments(geth ethClient) error {
	debug("relay.watchErc20Payments.start chainID=%d", geth.chainID)

	var (
		start = now()
		ctx   = context.Background()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters         = make(map[common.Hash]PaymentWaiter)
		topics          [][]any
		erc20AddressSet = make(map[common.Address]struct{})
	)

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr
		FROM payments
		WHERE orderPayedAt IS NULL
			AND erc20TokenAddr IS NOT NULL -- see watchErc20Payments()
			AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal, &waiter.erc20TokenAddr)
		check(err)
		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}

		erc20AddressSet[*waiter.erc20TokenAddr] = struct{}{}

		// right-align the purchase address to 32 bytes so we can use it as a topic
		var purchaseAddrAsHash common.Hash
		copy(purchaseAddrAsHash[12:], waiter.purchaseAddr.Bytes())
		waiters[purchaseAddrAsHash] = waiter

		topics = append(topics, []any{
			eventSignatureTransferErc20,
			nil,
			purchaseAddrAsHash})
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.watchErc20Payments.noOpenPayments took=%d", took(start))
		time.Sleep(ethereumBlockInterval)
		return nil
	}

	var wsURLs []string
	for _, u := range geth.rpcUrls {
		if !strings.HasPrefix(u, "ws") {
			continue
		}
		wsURLs = append(wsURLs, u)
	}

	randomIndex := mrand.Intn(len(wsURLs))
	randomRPCURL := wsURLs[randomIndex]

	rpcClient, err := rpc.Dial(randomRPCURL)
	if err != nil {
		return err
	}
	defer rpcClient.Close()

	var currentBlockNo hexutil.Uint64
	err = rpcClient.CallContext(ctx, &currentBlockNo, "eth_blockNumber")
	if err != nil {
		return err
	}

	debug("relay.watchErc20Payments.starting currentBlock=%d", currentBlockNo)

	// turn set into a list
	erc20Addresses := make([]common.Address, len(erc20AddressSet))
	i := 0
	for addr := range erc20AddressSet {
		copy(erc20Addresses[i][:], addr[:])
		i++
	}

	ch := make(chan types.Log)
	arg := map[string]interface{}{
		"address": erc20Addresses,
		// "topics":  topics,
		"topics": [][]common.Hash{
			{eventSignatureTransferErc20},
		},
	}
	arg["fromBlock"] = "0x" + strconv.FormatUint(uint64(currentBlockNo), 16)
	arg["toBlock"] = "0x" + strconv.FormatUint(uint64(currentBlockNo)*2, 16)

	debug("relay.watchErc20Payments.newSubscription from=%d", currentBlockNo)

	ctx, cancel := context.WithCancel(r.ethPaymentsContext)
	defer cancel()

	subscription, err := rpcClient.EthSubscribe(ctx, ch, "logs", arg)
	if err != nil {
		return fmt.Errorf("relay.watchErc20Payments.EthSubscribeFailed err=%s", err)
	}
	defer subscription.Unsubscribe()

	errch := subscription.Err()
	i = 0
	var lastBlockNo uint64

watch:
	for {
		select {
		case <-ctx.Done():
			log("context done")
			break watch
		case err := <-errch:
			log("relay.watchErc20Payments err=%s", err)
			break watch
		case vLog := <-ch:
			log("relay.watchErc20Payments i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			i++
			// debug("relay.watchErc20Payments.checking block=%d", vLog.BlockNumber)
			debug("relay.watchErc20Payments.checking topics=%#v", vLog.Topics[1:])
			fromHash := vLog.Topics[1]
			toHash := vLog.Topics[2]

			waiter, has := waiters[toHash]
			if has && waiter.erc20TokenAddr.Cmp(vLog.Address) == 0 {
				// We found a transfer to our address!
				orderID := waiter.orderID

				_, has := r.ordersByOrderID.get(orderID)
				assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

				evts, err := geth.erc20ContractABI.Unpack("Transfer", vLog.Data)
				if err != nil {
					log("relay.watchErc20Payments.transferErc20.failedToUnpackTransfer tx=%s err=%s", vLog.TxHash.Hex(), err)
					continue
				}

				inTx, ok := evts[0].(*big.Int)
				assertWithMessage(ok, fmt.Sprintf("unexpected unpack result for field 0 - type=%T", evts[0]))
				debug("relay.watchErc20Payments.foundTransfer orderId=%s from=%s to=%s amount=%s", orderID, fromHash.Hex(), toHash.Hex(), inTx.String())

				waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
				if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
					// it is larger or equal

					op := PaymentFoundInternalOp{
						orderID: orderID,
						txHash:  vLog.TxHash,
						done:    make(chan struct{}),
					}
					r.opsInternal <- &op
					<-op.done

					delete(waiters, toHash)
					log("relay.watchErc20Payments.completed orderId=%s", orderID)

				} else {
					// it is still smaller
					log("relay.watchErc20Payments.partial orderId=%s inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
					_, err = r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
					check(err)
				}
			} else {
				spew.Dump(vLog)
				log("relay.watchErc20Payments.noWaiter inTx=%s", vLog.TxHash.Hex())
			}
			// TODO: are logs always emitted in order?
			if vLog.BlockNumber > lastBlockNo {
				lastBlockNo = vLog.BlockNumber
			}
		}
	}
	if lastBlockNo > 0 {
		lastBlockBig := new(big.Int).SetUint64(lastBlockNo)
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(lastBlockBig) == -1 {
				continue
			}
			// move up block number
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE orderId = $1;`
			_, err = r.connPool.Exec(context.Background(), updateLastBlockNoQuery, waiter.orderID, uint64(currentBlockNo))
			check(err)
			debug("relay.watchErc20Payments.advance orderId=%x newLastBlock=%s", waiter.orderID, waiter.lastBlockNo.String())
		}
	}
	stillWaiting := len(waiters)
	debug("relay.watchErc20Payments.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_erc20_open", uint64(stillWaiting))
	return nil
}

func (r *Relay) watchPaymentMade(geth ethClient) error {
	debug("relay.watchPaymentMade.start chainID=%d", geth.chainID)

	var (
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Hash]PaymentWaiter)
	)

	ctx, cancel := context.WithCancel(r.ethPaymentsContext)
	defer cancel()

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, paymentId, lastBlockNo
		FROM payments
		WHERE orderPayedAt IS NULL AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.paymentId, &waiter.lastBlockNo)
		check(err)
		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		pid := common.Hash(waiter.paymentId.Bytes())
		//debug("relay.watchPaymentMade.want pid=%s", pid.Hex())
		waiters[pid] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.watchPaymentMade.noOpenPayments took=%d", took(start))
		return nil
	}

	gethClient, err := geth.getClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	// Get the latest block number.
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("relay.watchPaymentMade.blockNumber err=%s", err)
	}

	debug("relay.watchPaymentMade.starting currentBlock=%d", currentBlockNoInt)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	qry := ethereum.FilterQuery{
		Addresses: []common.Address{geth.contractAddresses.Payments},
		FromBlock: lowestLastBlock,
		ToBlock:   currentBlockNo,
		Topics: [][]common.Hash{
			{eventSignaturePaymentMade},
		},
	}
	logs, err := gethClient.FilterLogs(ctx, qry)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			debug("relay.watchPaymentMade.noNewBlocks took=%d", took(start))
			return nil // possibly no new block, dont try again immediatly
		}
		return err
	}

	// iterate over all matching logs of events from that erc20 contract with the transfer signature
	var lastBlockNo uint64

	for _, vLog := range logs {
		//debug("relay.watchPaymentMade.checking block=%d", vLog.BlockNumber)

		var paymentIdHash = common.Hash(vLog.Topics[1])
		//debug("relay.watchPaymentMade.seen pid=%s", paymentIdHash.Hex())

		if waiter, has := waiters[paymentIdHash]; has {
			orderID := waiter.orderID
			//debug("relay.watchPaymentMade.found cartId=%s txHash=%x", orderID, vLog.TxHash)

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			op := PaymentFoundInternalOp{
				orderID: orderID,
				txHash:  vLog.TxHash,
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			delete(waiters, paymentIdHash)
			log("relay.watchPaymentMade.completed cartId=%s txHash=%x", orderID, vLog.TxHash)
		}
		if vLog.BlockNumber > lastBlockNo {
			lastBlockNo = vLog.BlockNumber
		}
	}
	if lastBlockNo > 0 {
		lastBlockBig := new(big.Int).SetUint64(lastBlockNo)
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(lastBlockBig) == -1 {
				continue
			}
			// move up block number
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE cartId = $1;`
			_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, waiter.orderID, lastBlockNo)
			check(err)
			debug("relay.watchPaymentMade.advance cartId=%x newLastBlock=%s", waiter.orderID, waiter.lastBlockNo.String())
		}
	}
	stillWaiting := len(waiters)
	debug("relay.watchPaymentMade.finish elapsed=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_open", uint64(stillWaiting))
	return nil
}
