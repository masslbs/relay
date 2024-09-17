// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"math/big"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v4"
	"github.com/ssgreg/repeat"
)

/* TODO: a lot of this need to be revamped to properly handle re-org.
   we should probably collect what we do now as witnesses, wait N blocks, and then fire the paymentMadeOp.
*/

// PaymentWaiter is a struct that holds the state of a order that is waiting for payment.
type PaymentWaiter struct {
	shopID          shopID
	orderID         uint64
	itemsLockedAt   time.Time
	paymentChosenAt time.Time
	chainID         uint64
	purchaseAddr    common.Address
	lastBlockNo     SQLStringBigInt
	coinsPayed      SQLStringBigInt
	coinsTotal      SQLStringBigInt
	paymentId       []byte

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
			shopId := new(big.Int).SetBytes(vLog.Topics[1].Bytes())
			debug("watcher.subscribeAccountEvents add=%v rm=%v shop=%s", isAdd, isRemove, shopId)

			evts, err := geth.shopRegContractABI.Unpack(eventName, vLog.Data)
			if err != nil {
				err = fmt.Errorf("watcher.subscribeAccountEvents.failedToUnpack event=%s tx=%s err=%s", eventName, vLog.TxHash.Hex(), err)
				return repeat.HintTemporary(err)
			}

			// check if we are serving this store
			var dbShopID shopID
			err = r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, shopId.String()).Scan(&dbShopID)
			if err == pgx.ErrNoRows {
				continue watch // not for this relay
			} else if err != nil {
				check(err)
			}

			//spew.Dump(evts)

			userAddr, ok := evts[0].(common.Address)
			if !ok {
				err = fmt.Errorf("watcher.subscribeAccountEvents.castOfEventFailed event=%s type=%T tx=%s", eventName, evts[0], vLog.TxHash.Hex())
				return repeat.HintTemporary(err)
			}

			op := &OnchainActionInternalOp{
				shopID: dbShopID,
				user:   userAddr,
				add:    isAdd,
				txHash: vLog.TxHash,
			}
			r.opsInternal <- op
			log("watcher.subscribeAccountEvents.%s user=%s shop=%s", eventName, userAddr, shopId)

			i++
		}
	}

	log("watcher.subscribeAccountEvents.exited i=%d took=%d", i, took(start))
	return nil
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

			var paymentIdHash = vLog.Topics[1]

			var waiter PaymentWaiter
			openPaymentsQry := `SELECT shopId, orderId, paymentChosenAt
					FROM payments
					WHERE
					payedAt IS NULL
					AND paymentChosenAt >= NOW() - INTERVAL '1 day'
					AND paymentId = $1
					AND chainId = $2`
			err := r.connPool.QueryRow(ctx, openPaymentsQry, paymentIdHash.Bytes(), geth.chainID).Scan(&waiter.shopID, &waiter.orderID, &waiter.paymentChosenAt)
			if err == pgx.ErrNoRows {
				continue
			} else if err != nil {
				check(err)
			}

			orderID := waiter.orderID
			log("watcher.subscribeFilterLogsPaymentsMade.found orderId=%d txHash=%x", orderID, vLog.TxHash)

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%d", orderID))

			op := PaymentFoundInternalOp{
				shopID:  waiter.shopID,
				orderID: waiter.orderID,
				txHash:  &Hash{Raw: vLog.TxHash.Bytes()},
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			log("watcher.subscribeFilterLogsPaymentsMade.completed orderId=%d txHash=%x", orderID, vLog.TxHash)
		}
	}

	log("watcher.subscribeFilterLogsPaymentsMade.exited took=%d", took(start))
	return nil
}

func (r *Relay) subscribeFilterLogsERC20Transfers(geth *ethClient) error {
	debug("watcher.subscribeFilterLogsERC20Transfers.start chainID=%d", geth.chainID)

	var (
		start = now()
		ctx   = r.watcherContextERC20

		waiters         = make(map[common.Hash]PaymentWaiter)
		erc20AddressSet = make(map[common.Address]struct{})
	)

	openPaymentsQry := `SELECT shopId, orderId, paymentChosenAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr
				FROM payments
				WHERE payedAt IS NULL
					AND erc20TokenAddr IS NOT NULL -- see subscribeFilterLogsERC20Transfers()
					AND paymentChosenAt >= NOW() - INTERVAL '1 day'
		            AND chainId = $1
		ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry, geth.chainID)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.shopID, &waiter.orderID, &waiter.paymentChosenAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal, &waiter.erc20TokenAddr)
		check(err)

		erc20AddressSet[*waiter.erc20TokenAddr] = struct{}{}

		// right-align the purchase address to 32 bytes so we can use it as a topic
		var purchaseAddrAsHash common.Hash
		copy(purchaseAddrAsHash[12:], waiter.purchaseAddr.Bytes())
		waiters[purchaseAddrAsHash] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("watcher.subscribeFilterLogsERC20Transfers.noOpenPayments took=%d", took(start))
		return nil
	}

	rpc, err := geth.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
	}

	// turn set into a list
	erc20Addresses := make([]common.Address, len(erc20AddressSet))
	i := 0
	for addr := range erc20AddressSet {
		copy(erc20Addresses[i][:], addr[:])
		i++
	}

	ch := make(chan types.Log)
	arg := ethereum.FilterQuery{
		Addresses: erc20Addresses,
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

	var returnErr error = nil
watch:
	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			debug("watcher.subscribeFilterLogsERC20Transfers.contextDone err=%s", err)
			returnErr = repeat.HintTemporary(err)
			break watch
		case err := <-errch:
			debug("watcher.subscribeFilterLogsERC20Transfers.subscriptionBroke err=%s", err)
			returnErr = repeat.HintTemporary(err)
			break watch
		case vLog := <-ch:
			debug("watcher.subscribeFilterLogsERC20Transfers.checking block_tx=%s topics=%#v", vLog.BlockHash.Hex(), vLog.Topics[1:])
			fromHash := vLog.Topics[1]
			toHash := vLog.Topics[2]

			waiter, has := waiters[toHash]
			if has && waiter.erc20TokenAddr.Cmp(vLog.Address) == 0 {
				// We found a transfer to our address!
				orderID := waiter.orderID

				_, has := r.ordersByOrderID.get(orderID)
				assertWithMessage(has, fmt.Sprintf("order not found for orderId=%d", orderID))

				evts, err := geth.erc20ContractABI.Unpack("Transfer", vLog.Data)
				if err != nil {
					log("watcher.subscribeFilterLogsERC20Transfers.transferErc20.failedToUnpackTransfer tx=%s err=%s", vLog.TxHash.Hex(), err)
					continue
				}

				inTx, ok := evts[0].(*big.Int)
				assertWithMessage(ok, fmt.Sprintf("unexpected unpack result for field 0 - type=%T", evts[0]))
				debug("watcher.subscribeFilterLogsERC20Transfers.foundTransfer orderId=%d from=%s to=%s amount=%s", orderID, fromHash.Hex(), toHash.Hex(), inTx.String())

				waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
				if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
					// it is larger or equal

					op := PaymentFoundInternalOp{
						shopID:  waiter.shopID,
						orderID: waiter.orderID,
						txHash:  &Hash{Raw: vLog.TxHash.Bytes()},
						done:    make(chan struct{}),
					}
					r.opsInternal <- &op
					<-op.done

					delete(waiters, toHash)
					log("watcher.subscribeFilterLogsERC20Transfers.completed orderId=%d", orderID)

				} else {
					// it is still smaller
					log("watcher.subscribeFilterLogsERC20Transfers.partial orderId=%d inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
					_, err = r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
					check(err)
				}
			} else {
				log("watcher.subscribeFilterLogsERC20Transfers.noWaiter inTx=%s", vLog.TxHash.Hex())
			}
		}
	}
	stillWaiting := len(waiters)
	debug("watcher.subscribeFilterLogsERC20Transfers.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.gaugeSet("relay_payments_erc20_open", float64(stillWaiting))
	return returnErr

}

func (r *Relay) subscribeNewHeadsForEther(client *ethClient) error {
	debug("watcher.subscribeNewHeadsForEther.start chainID=%d", client.chainID)

	var (
		ctx   = r.watcherContextEther
		start = now()
	)

	var waiters = make(map[common.Address]PaymentWaiter)

	openPaymentsQry := `SELECT shopId, orderId, paymentChosenAt, purchaseAddr, coinsTotal
			FROM payments
			WHERE payedAt IS NULL
				AND erc20TokenAddr IS NULL -- see watchErc20Payments()
				AND paymentChosenAt >= NOW() - INTERVAL '1 day'
		        AND chainId = $1
		 ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry, client.chainID)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.shopID, &waiter.orderID, &waiter.paymentChosenAt, &waiter.purchaseAddr, &waiter.coinsTotal)
		check(err)

		waiters[waiter.purchaseAddr] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("watcher.subscribeNewHeadsForEther.noOpenPayments took=%d", took(start))
		return nil
	}

	debug("watcher.subscribeNewHeadsForEther.dbRead took=%d waiters=%d", took(start), len(waiters))

	rpc, err := client.getWebsocketRPC()
	if err != nil {
		return repeat.HintTemporary(err)
	}

	ch := make(chan *types.Header)
	sub, err := rpc.SubscribeNewHead(ctx, ch)
	if err != nil {
		err = fmt.Errorf("subNewHead failed: %w", err)
		return repeat.HintTemporary(err)

	}
	defer sub.Unsubscribe()
	errch := sub.Err()

	debug("watcher.subscribeNewHeadsForEther.waitForNextBlock")
	select {

	case <-ctx.Done():
		err = ctx.Err()
		debug("watcher.subscribeNewHeadsForEther.contextDone err=%s", err)
		return repeat.HintTemporary(err)

	case err := <-errch:
		debug("watcher.subscribeNewHeadsForEther.subscribeBroke err=%s", err)
		err = fmt.Errorf("subscription broke: %w", err)
		return repeat.HintTemporary(err)

	case newHead := <-ch:
		debug("watcher.subscribeNewHeadsForEther.newHead block=%s", newHead.Number)
		for addr, waiter := range waiters {
			balance, err := rpc.BalanceAt(ctx, addr, newHead.Number)
			if err != nil {
				err = fmt.Errorf("subscribeNewHeadsForEther.balanceAtFailed addr=%s block=%s err=%w", addr.Hex(), newHead.Number, err)
				debug(err.Error())
				return repeat.HintTemporary(err)
			}

			if balance.Cmp(&waiter.coinsTotal.Int) == -1 {
				continue
			}

			debug("watcher.subscribeNewHeadsForEther.checkTx checkingBlock=%s to=%s", newHead.Hash().Hex(), addr.Hex())
			orderID := waiter.orderID
			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%d", orderID))

			op := PaymentFoundInternalOp{
				shopID:    waiter.shopID,
				orderID:   orderID,
				blockHash: &Hash{Raw: newHead.Hash().Bytes()},
				done:      make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // wait for write

			delete(waiters, waiter.purchaseAddr)
			log("watcher.subscribeNewHeadsForEther.completed orderId=%d", orderID)
		}
	}

	stillWaiting := len(waiters)
	debug("watcher.subscribeNewHeadsForEther.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.gaugeSet("relay_payments_eth_open", float64(stillWaiting))
	return nil
}
