// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/ssgreg/repeat"
)

/* TODO: a lot of this need to be revamped to properly handle re-org.
   we should probably collect what we do now as witnesses, wait N blocks, and then fire the paymentMadeOp.
*/

// PaymentWaiter is a struct that holds the state of a order that is waiting for payment.
type PaymentWaiter struct {
	shopID          ObjectIDArray
	orderID         ObjectIDArray
	paymentChosenAt time.Time
	chainID         uint64
	purchaseAddr    common.Address
	lastBlockNo     SQLStringBigInt
	coinsTotal      SQLStringBigInt
	paymentID       []byte

	// (optional) contract of the erc20 that we are looking for
	erc20TokenAddr *common.Address
}

var (
	eventSignatureTransferErc20 = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	eventSignaturePaymentMade   = crypto.Keccak256Hash([]byte("PaymentMade(uint256)"))
	eventSignatureUserAdded     = crypto.Keccak256Hash([]byte("UserAdded(uint256,address,uint256)"))
	eventSignatureUserRemoved   = crypto.Keccak256Hash([]byte("UserRemoved(uint256,address)"))
	// TODO
	//eventSignaturePermissionAdded   = crypto.Keccak256Hash([]byte("PermissionAdded(uint256,address,uint8)"))
	//eventSignaturePermissionRemoved = crypto.Keccak256Hash([]byte("PermissionRemoved(uint256,address,uint8)"))
)

// OnChain account actions
func (r *Relay) subscribeAccountEvents(geth *ethClient) error {
	log("watcher.subscribeAccountEvents.start chainID=%d", geth.chainID)

	var start = now()

	ctx := context.Background()

	gethClient, err := geth.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
	}

	qry := ethereum.FilterQuery{
		Addresses: []common.Address{
			geth.contractAddresses.ShopRegistry,
		},
		Topics: [][]common.Hash{
			{eventSignatureUserAdded, eventSignatureUserRemoved},
		},
	}

	ch := make(chan types.Log)
	sub, err := gethClient.SubscribeFilterLogs(ctx, qry, ch)
	if err != nil {
		err = fmt.Errorf("watcher.subscribeAccountEvents.ethSubscribeFailed err=%s", err)
		return repeat.HintTemporary(err)
	}
	defer sub.Unsubscribe()
	errch := sub.Err()
	i := 0

watch:
	for {
		select {
		case err := <-errch:
			log("watcher.subscribeAccountEvents.subscribeFilterLogsBroke err=%s", err)
			break watch
		case vLog := <-ch:
			debug("watcher.subscribeAccountEvents.newLog i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			eventName := "undefined"
			isAdd := vLog.Topics[0].Cmp(eventSignatureUserAdded) == 0
			isRemove := vLog.Topics[0].Cmp(eventSignatureUserRemoved) == 0
			if isAdd {
				eventName = "UserAdded"
			} else if isRemove {
				eventName = "UserRemoved"
			} else {
				return fmt.Errorf("unhandeld event type: %s", vLog.Topics[0].Hex())
			}
			eventShopID := new(big.Int).SetBytes(vLog.Topics[1].Bytes())
			debug("watcher.subscribeAccountEvents add=%v rm=%v shop=%s", isAdd, isRemove, eventShopID)

			evts, err := geth.shopRegContractABI.Unpack(eventName, vLog.Data)
			if err != nil {
				err = fmt.Errorf("watcher.subscribeAccountEvents.failedToUnpack event=%s tx=%s err=%s", eventName, vLog.TxHash.Hex(), err)
				return repeat.HintTemporary(err)
			}

			// check if we are serving this store
			var dbShopID uint64
			err = r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, eventShopID.String()).Scan(&dbShopID)
			if err == pgx.ErrNoRows {
				continue watch // not for this relay
			} else if err != nil {
				check(err)
			}
			var shopID ObjectIDArray
			binary.BigEndian.PutUint64(shopID[:], dbShopID)

			//spew.Dump(evts)

			userAddr, ok := evts[0].(common.Address)
			if !ok {
				err = fmt.Errorf("watcher.subscribeAccountEvents.castOfEventFailed event=%s type=%T tx=%s", eventName, evts[0], vLog.TxHash.Hex())
				return repeat.HintTemporary(err)
			}

			op := &OnchainActionInternalOp{
				shopID: shopID,
				user:   userAddr,
				add:    isAdd,
				txHash: vLog.TxHash,
			}
			r.opsInternal <- op
			log("watcher.subscribeAccountEvents.%s user=%s shop=%d", eventName, userAddr, dbShopID)

			i++
		}
	}

	log("watcher.subscribeAccountEvents.exited i=%d took=%d", i, took(start))
	return nil
}

func (r *Relay) getPaymentWaiterForERC20Transfer(chainID uint64, purchaseAddr, tokenAddr common.Address) (PaymentWaiter, error) {
	var order PaymentWaiter
	var sid, oid []byte

	query := `
		SELECT shopId, orderId, paymentChosenAt, purchaseAddr, lastBlockNo, coinsTotal, erc20TokenAddr
		FROM payments
		WHERE payedAt IS NULL
			AND erc20TokenAddr = $1
			AND purchaseAddr = $2
			AND paymentChosenAt >= NOW() - INTERVAL '1 day'
			AND chainId = $3
		LIMIT 1
	`

	err := r.connPool.QueryRow(context.Background(), query, tokenAddr, purchaseAddr, chainID).Scan(
		&sid, &oid, &order.paymentChosenAt, &order.purchaseAddr,
		&order.lastBlockNo, &order.coinsTotal, &order.erc20TokenAddr,
	)

	if err != nil {
		return PaymentWaiter{}, err
	}

	order.shopID = ObjectIDArray(sid)
	order.orderID = ObjectIDArray(oid)

	return order, nil
}

func (r *Relay) getPaymentWaiterForPaymentMade(chainID uint64, paymentIDHash common.Hash) (PaymentWaiter, error) {
	var order PaymentWaiter
	var sid, oid []byte

	const query = `SELECT shopId, orderId, paymentChosenAt
	FROM payments
	WHERE
	payedAt IS NULL
	AND paymentChosenAt >= NOW() - INTERVAL '1 day'
	AND paymentID = $1
	AND chainId = $2`

	err := r.connPool.QueryRow(context.Background(), query, paymentIDHash.Bytes(), chainID).Scan(&sid, &oid, &order.paymentChosenAt)
	if err != nil {
		return PaymentWaiter{}, err
	}

	assert(len(sid) == 8)
	assert(len(oid) == 8)
	order.shopID = ObjectIDArray(sid)
	order.orderID = ObjectIDArray(oid)

	return order, nil
}

// direct contract calls, done via pay() that emit PaymentMade events
func (r *Relay) subscribeFilterLogsPaymentsMade(geth *ethClient) error {
	log("watcher.subscribeFilterLogsPaymentsMade.start chainID=%d", geth.chainID)

	var start = now()

	ctx := context.Background()

	gethClient, err := geth.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
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
	sub, err := gethClient.SubscribeFilterLogs(ctx, qry, ch)
	if err != nil {
		return fmt.Errorf("watcher.subscribeFilterLogsPaymentsMade.ethSubscribeFailed err=%s", err)
	}
	defer sub.Unsubscribe()
	errch := sub.Err()
	i := 0

watch:
	for {
		select {
		case err := <-errch:
			log("watcher.subscribeFilterLogsPaymentsMade.subscribeFilterLogsBroke err=%s", err)
			break watch
		case vLog := <-ch:
			debug("watcher.subscribeFilterLogsPaymentsMade.newLog i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			i++

			var paymentIDHash = vLog.Topics[1]
			order, err := r.getPaymentWaiterForPaymentMade(geth.chainID, paymentIDHash)
			if err == pgx.ErrNoRows {
				continue
			} else if err != nil {
				check(err)
			}
			orderID := order.orderID
			log("watcher.subscribeFilterLogsPaymentsMade.found orderId=%x txHash=%x", orderID, vLog.TxHash)

			op := PaymentFoundInternalOp{
				shopID:    order.shopID,
				orderID:   order.orderID,
				txHash:    &vLog.TxHash,
				blockHash: vLog.BlockHash,
				done:      make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			log("watcher.subscribeFilterLogsPaymentsMade.completed orderId=%x txHash=%x", orderID, vLog.TxHash)
		}
	}

	log("watcher.subscribeFilterLogsPaymentsMade.exited took=%d", took(start))
	return nil
}

func (r *Relay) subscribeFilterLogsERC20Transfers(geth *ethClient) error {
	debug("watcher.subscribeFilterLogsERC20Transfers.start chainID=%d", geth.chainID)

	var ctx = context.Background()

	rpc, err := geth.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
	}

	ch := make(chan types.Log)
	arg := ethereum.FilterQuery{
		Topics: [][]common.Hash{
			{eventSignatureTransferErc20},
		},
	}

	subscription, err := rpc.SubscribeFilterLogs(ctx, arg, ch)
	if err != nil {
		err = fmt.Errorf("watcher.subscribeFilterLogsERC20Transfers.EthSubscribeFailed: %w", err)
		return repeat.HintTemporary(err)
	}
	defer subscription.Unsubscribe()

	errch := subscription.Err()

	for {
		select {
		case err := <-errch:
			debug("watcher.subscribeFilterLogsERC20Transfers.subscriptionBroke err=%s", err)
			return repeat.HintTemporary(err)
		case vLog := <-ch:
			if len(vLog.Topics) < 3 {
				debug("watcher.subscribeFilterLogsERC20Transfers.skipped block_tx=%s topics=%#v", vLog.BlockHash.Hex(), vLog.Topics)
				continue
			}

			// Query for the payment order on each log received
			toHash := vLog.Topics[2]
			paymentAddr := common.Address(toHash[12:]) // slice 20 bytes out of topic[2]
			order, err := r.getPaymentWaiterForERC20Transfer(geth.chainID, paymentAddr, vLog.Address)
			if err == pgx.ErrNoRows {
				continue
			} else if err != nil {
				err = fmt.Errorf("watcher.subscribeFilterLogsERC20Transfers.getPaymentWaiterFailed tx=%s err=%s", vLog.TxHash.Hex(), err)
				check(err)
			}
			log("watcher.subscribeFilterLogsERC20Transfers.found tx=%s order=%x", vLog.TxHash.Hex(), order.orderID)

			// Process the transfer
			if err := r.processERC20Transfer(geth, order, vLog); err != nil {
				log("watcher.subscribeFilterLogsERC20Transfers.processTransferFailed order=%x err=%s", order.orderID, err)
			}
		}
	}
}

func (r *Relay) processERC20Transfer(geth *ethClient, order PaymentWaiter, vLog types.Log) error {
	evts, err := geth.erc20ContractABI.Unpack("Transfer", vLog.Data)
	if err != nil {
		return fmt.Errorf("failedToUnpackTransfer tx=%s err=%s", vLog.TxHash.Hex(), err)
	}

	inTx, ok := evts[0].(*big.Int)
	if !ok {
		return fmt.Errorf("unexpected unpack result for field 0 - type=%T", evts[0])
	}

	debug("watcher.processERC20Transfer.foundTransfer orderId=%x from=%s to=%s amount=%s",
		order.orderID, vLog.Topics[1].Hex(), vLog.Topics[2].Hex(), inTx.String())

	if inTx.Cmp(&order.coinsTotal.Int) != -1 {
		// it is larger or equal
		op := PaymentFoundInternalOp{
			shopID:    order.shopID,
			orderID:   order.orderID,
			txHash:    &vLog.TxHash,
			blockHash: vLog.BlockHash,
			done:      make(chan struct{}),
		}
		r.opsInternal <- &op
		<-op.done

		log("watcher.processERC20Transfer.completed orderId=%x", order.orderID)
	}

	return nil
}
func (r *Relay) subscribeNewHeadsForEther(client *ethClient) error {
	debug("watcher.subscribeNewHeadsForEther.start chainID=%d", client.chainID)

	ctx := context.Background()

	rpc, err := client.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
	}

	ch := make(chan *types.Header)
	sub, err := rpc.SubscribeNewHead(ctx, ch)
	if err != nil {
		return repeat.HintTemporary(err)
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-sub.Err():
			return repeat.HintTemporary(err)
		case newHead := <-ch:
			start := now()
			orders, err := r.getOpenEtherPayments(ctx, client.chainID)
			if err != nil {
				return fmt.Errorf("failed to get open payments: %w", err)
			}

			if len(orders) == 0 {
				debug("watcher.processNewHeadForEther.noOpenPayments took=%d", took(start))
				continue
			}

			debug("watcher.processNewHeadForEther.dbRead took=%d orders=%d", took(start), len(orders))

			// Process the new block for each order
			for _, order := range orders {
				addr := order.purchaseAddr
				balance, err := rpc.BalanceAt(ctx, addr, newHead.Number)
				if err != nil {
					err = fmt.Errorf("subscribeNewHeadsForEther.balanceAtFailed addr=%s block=%s err=%w", addr.Hex(), newHead.Number, err)
					debug(err.Error())
					return repeat.HintTemporary(err)
				}

				if balance.Cmp(&order.coinsTotal.Int) == -1 {
					continue
				}

				debug("watcher.subscribeNewHeadsForEther.checkTx checkingBlock=%s to=%s", newHead.Hash().Hex(), addr.Hex())
				orderID := order.orderID

				op := PaymentFoundInternalOp{
					shopID:    order.shopID,
					orderID:   order.orderID,
					blockHash: newHead.Hash(),
					done:      make(chan struct{}),
				}
				r.opsInternal <- &op
				<-op.done // wait for write

				log("watcher.subscribeNewHeadsForEther.completed orderId=%x", orderID)
			}
		}
	}
}

func (r *Relay) getOpenEtherPayments(ctx context.Context, chainID uint64) (map[common.Address]PaymentWaiter, error) {
	orders := make(map[common.Address]PaymentWaiter)

	openPaymentsQry := `SELECT shopId, orderId, paymentChosenAt, purchaseAddr, coinsTotal
			FROM payments
			WHERE payedAt IS NULL
				AND erc20TokenAddr IS NULL
				AND paymentChosenAt >= NOW() - INTERVAL '1 day'
		        AND chainId = $1
		 ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to query open payments: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var order PaymentWaiter
		var sid, oid []byte
		err := rows.Scan(&sid, &oid, &order.paymentChosenAt, &order.purchaseAddr, &order.coinsTotal)
		if err != nil {
			return nil, fmt.Errorf("failed to scan open payments from database: %w", err)
		}

		assert(len(sid) == 8)
		order.shopID = ObjectIDArray(sid)
		assert(len(oid) == 8)
		order.orderID = ObjectIDArray(oid)

		orders[order.purchaseAddr] = order
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over open payments: %w", err)
	}

	return orders, nil
}
