// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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
)

type ethClient struct {
	*ethclient.Client
	chainID uint

	gasTipCap *big.Int
	gasFeeCap *big.Int

	stores         *RegStore
	relays         *RegRelay
	paymentFactory *PaymentFactory

	erc20ContractABI abi.ABI

	contractAddresses struct {
		PaymentFactory common.Address `json:"PaymentFactory"`
		StoreRegistry  common.Address `json:"StoreReg"`
		RelayRegistry  common.Address `json:"RelayReg"`
	}
	secret *ecdsa.PrivateKey
	wallet common.Address

	relayTokenID *big.Int
}

//go:embed gen_contract_addresses.json
var genContractAddresses embed.FS

func newEthClient() *ethClient {
	var c ethClient
	c.chainID = uint(mustGetEnvInt("ETH_CHAIN_ID"))

	rpcUrl := mustGetEnvString("ETH_RPC_ENDPOINT")
	var err error
	c.Client, err = ethclient.Dial(rpcUrl)
	check(err)

	log("ethClient chainId=%d rpc=%s", c.chainID, rpcUrl)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	// check rpc works
	err = c.updateGasLimit(ctx)
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
	assert(c.hasBalance(c.wallet))

	addrData, err := genContractAddresses.ReadFile("gen_contract_addresses.json")
	check(err)
	err = json.Unmarshal(addrData, &c.contractAddresses)
	check(err)

	c.stores, err = NewRegStore(c.contractAddresses.StoreRegistry, c.Client)
	check(err)
	log("ethClient.newEthClient storeRegAddr=%s", c.contractAddresses.StoreRegistry.Hex())

	c.relays, err = NewRegRelay(c.contractAddresses.RelayRegistry, c.Client)
	check(err)
	log("ethClient.newEthClient relayRegAddr=%s", c.contractAddresses.RelayRegistry.Hex())

	c.paymentFactory, err = NewPaymentFactory(c.contractAddresses.PaymentFactory, c.Client)
	check(err)
	log("ethClient.newEthClient paymentFactoryAddr=%s", c.contractAddresses.PaymentFactory.Hex())

	c.erc20ContractABI, err = abi.JSON(strings.NewReader(ERC20MetaData.ABI))
	check(err)

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    c.wallet,
		Context: ctx,
	}

	var h [32]byte
	addr, err := c.paymentFactory.GetPaymentAddress(callOpts, c.wallet, c.wallet, big.NewInt(123), common.Address{}, h)
	check(err)
	log("ethClient.testing PaymentAddress=%s", addr.Hex())

	// register a new nft for the relay
	relayTokenID := new(big.Int)
	if nftIDStr := os.Getenv("RELAY_NFT_ID"); nftIDStr != "" {
		buf, err := hex.DecodeString(nftIDStr)
		check(err)
		assertWithMessage(len(buf) == 32, fmt.Sprintf("expected 32bytes of data in RELAY_NFT_ID. got %d", len(buf)))
		relayTokenID.SetBytes(buf)

		nftOwner, err := c.relays.OwnerOf(callOpts, relayTokenID)
		check(err)
		assertWithMessage(nftOwner.Cmp(c.wallet) == 0, fmt.Sprintf("passed NFT is owned by %s", nftOwner))
	} else { // in testing, always create a new nft
		buf := make([]byte, 32)
		rand.Read(buf)
		relayTokenID.SetBytes(buf)

		// working around a little qurik where big.Int.Text(16) doesn't encode zeros as expected.
		// if the final or last word is 0, it just omits it. This trips up the python library.
		// This way we should also get a non-zero end byte.
		buf[0] ^= 0xff
		buf[31] ^= 0xff

		txOpts, err := c.makeTxOpts(ctx)
		check(err)
		tx, err := c.relays.Mint(txOpts, relayTokenID, c.wallet, fmt.Sprintf("http://localhost:%d/relay_nft?token=%s", mustGetEnvInt("PORT"), relayTokenID))
		check(err)

		err = c.checkTransaction(ctx, tx)
		check(err)
	}

	log("ethClient.relayNft token=%s", relayTokenID)
	c.relayTokenID = relayTokenID

	return &c
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

func (c ethClient) checkTransaction(ctx context.Context, tx *types.Transaction) error {
	receipt, err := bind.WaitMined(ctx, c.Client, tx)
	if err != nil {
		return fmt.Errorf("waiting for mint failed: %w", err)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("call failed with status: %d", receipt.Status)
	}
	return nil
}

func (c *ethClient) updateGasLimit(ctx context.Context) error {
	var err error
	c.gasFeeCap, err = c.Client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("ethClient.updateGasLimit: gas price failed: %w", err)
	}
	log("ethClient.updateGasLimit gasFeeCap=%s", c.gasFeeCap)

	c.gasTipCap, err = c.Client.SuggestGasTipCap(ctx)
	if err != nil {
		return fmt.Errorf("ethClient.updateGasLimit: gas tip cap failed: %w", err)
	}
	log("ethClient.updateGasLimit gasTipCap=%s", c.gasTipCap)
	return nil
}

func (c ethClient) hasBalance(addr common.Address) bool {
	ctx := context.Background()
	currBlock, err := c.BlockNumber(ctx)
	check(err)

	balance, err := c.BalanceAt(ctx, addr, big.NewInt(int64(currBlock)))
	if err != nil {
		return false
	}
	log("ethClient balance=%d wallet=%s", balance.Int64(), addr.Hex())

	return balance.Int64() > 0
}

func (c ethClient) readRootHashForStore(storeID string) {
	ctx := context.Background()
	storeIDInt := new(big.Int)
	_, ok := storeIDInt.SetString(strings.TrimPrefix(storeID, "0x"), 16)
	if !ok {
		panic("Error parsing store ID")
	}

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    c.wallet,
		Context: ctx,
	}

	rootHash, err := c.stores.RootHashes(callOpts, storeIDInt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting root hash: ", err)
		return
	}
	fmt.Println("Current Root Hash: ", hex.EncodeToString(rootHash[:]))

	relayCount, err := c.stores.GetRelayCount(callOpts, storeIDInt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting relay count: ", err)
		return
	}
	fmt.Println("Current Relay Count: ", relayCount.Uint64())
}

/*
func (c ethClient) updateRootHash(_ requestID, newRootHash []byte) error {
	if len(newRootHash) != 32 {
		return fmt.Errorf("invalid root hash length: %d", len(newRootHash))
	}

	// TODO: query me
	var storeBigIntID big.Int

	ctx := context.Background()
	callOpts, err := c.makeTxOpts(ctx)
	if err != nil {
		return err
	}
	tx, err := c.stores.UpdateRootHash(callOpts, &storeBigIntID, [32]byte(newRootHash))
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
