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
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
	"github.com/ssgreg/repeat"
)

var relayKeyCardID requestID

type ethClient struct {
	rpcUrls []string
	chainID uint

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

func newEthClient() *ethClient {
	var c ethClient
	var err error

	c.chainID = uint(mustGetEnvInt("ETH_CHAIN_ID"))

	for _, urls := range strings.Split(mustGetEnvString("ETH_RPC_ENDPOINT"), ";") {
		c.rpcUrls = append(c.rpcUrls, urls)
	}

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

		// working around a little qurik where big.Int.Text(16) doesn't encode zeros as expected.
		// if the first word is 0, it just omits it. This trips up the python library, thinking it's just 31 bytes long
		// This way we should also get a non-zero end byte.
		buf[0] |= 0x80

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

/*
func (c ethClient) readRootHashForShop(ctx context.Context, shopID string) {
	shopReg, gethc, err := c.newShopReg(ctx)

	shopIDInt := new(big.Int)
	_, ok := shopIDInt.SetString(strings.TrimPrefix(shopID, "0x"), 16)
	if !ok {
		panic("Error parsing shop ID")
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    c.wallet,
		Context: ctx,
	}

	rootHash, err := c.shops.RootHashes(callOpts, shopIDInt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting root hash: ", err)
		return
	}
	fmt.Println("Current Root Hash: ", hex.EncodeToString(rootHash[:]))

	relayCount, err := c.shops.GetRelayCount(callOpts, shopIDInt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting relay count: ", err)
		return
	}
	fmt.Println("Current Relay Count: ", relayCount.Uint64())
}


func (c ethClient) updateRootHash(_ requestID, newRootHash []byte) error {
	if len(newRootHash) != 32 {
		return fmt.Errorf("invalid root hash length: %d", len(newRootHash))
	}

	// TODO: query me
	var shopBigIntID big.Int

	ctx := context.Background()
	callOpts, err := c.makeTxOpts(ctx)
	if err != nil {
		return err
	}
	tx, err := c.shops.UpdateRootHash(callOpts, &shopBigIntID, [32]byte(newRootHash))
	if err != nil {
		return fmt.Errorf("creating transaction failed: %w", err)
	}

	return c.checkTransaction(ctx, tx)
    }
*/

func (c ethClient) discoveryHandleFunc(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]any{
		"relay_token_id": hexutil.EncodeBig(c.relayTokenID),
		"chain_id":       c.chainID,
	})
	if err != nil {
		log("ethClient.discovery err=%s", err.Error())
	}
}
