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
)

// PaymentWaiter is a struct that holds the state of a order that is waiting for payment.
type PaymentWaiter struct {
	waiterID         requestID
	orderID          eventID
	orderFinalizedAt time.Time
	chainID          uint64
	purchaseAddr     common.Address
	lastBlockNo      SQLStringBigInt
	coinsPayed       SQLStringBigInt
	coinsTotal       SQLStringBigInt
	paymentId        []byte

	// (optional) contract of the erc20 that we are looking for
	erc20TokenAddr *common.Address

	// set if order was payed
	orderPayedAt *time.Time
	orderPayedTx *common.Hash
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)

	eventSignatureTransferErc20 = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	eventSignaturePaymentMade   = crypto.Keccak256Hash([]byte("PaymentMade(uint256)"))
)

// direct contract calls, done via pay() that emit PaymentMade events
func (r *Relay) subscribeFilterLogsPaymentsMade(geth *ethClient) error {
	log("relay.subscribeFilterLogsPaymentsMade.start chainID=%d", geth.chainID)

	var start = now()

	ctx := context.Background()

	gethClient, err := geth.getWebsocketRPC()
	if err != nil {
		return err
	}

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
	subscribeFilterLogsion, err := gethClient.SubscribeFilterLogs(ctx, qry, ch)
	if err != nil {
		return fmt.Errorf("relay.subscribeFilterLogsPaymentsMade.ethSubscribeFailed err=%s", err)
	}
	defer subscribeFilterLogsion.Unsubscribe()
	errch := subscribeFilterLogsion.Err()
	i := 0

	log("relay.subscribeFilterLogsPaymentsMade.startingBlockNo  current=%d", currentBlockNoInt)

watch:
	for {
		select {
		case err := <-errch:
			log("relay.subscribeFilterLogsPaymentsMade.subscribeFilterLogsionBroke err=%s", err)
			break watch
		case vLog := <-ch:
			debug("relay.subscribeFilterLogsPaymentsMade.newLog i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			i++

			var paymentIdHash = vLog.Topics[1]

			var waiter PaymentWaiter
			openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt
FROM payments
WHERE
orderPayedAt IS NULL
AND orderFinalizedAt >= NOW() - INTERVAL '1 day'
AND paymentId = $1
AND chainId = $2`
			err := r.connPool.QueryRow(ctx, openPaymentsQry, paymentIdHash.Bytes(), geth.chainID).Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt)
			if err == pgx.ErrNoRows {
				continue
			} else if err != nil {
				check(err)
			}

			orderID := waiter.orderID
			log("relay.subscribeFilterLogsPaymentsMade.found orderId=%s txHash=%x", orderID, vLog.TxHash)

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			op := PaymentFoundInternalOp{
				orderID: orderID,
				txHash:  vLog.TxHash,
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			log("relay.subscribeFilterLogsPaymentsMade.completed cartId=%s txHash=%x", orderID, vLog.TxHash)
		}
	}

	log("relay.subscribeFilterLogsPaymentsMade.exited took=%d", took(start))
	return nil
}

func (r *Relay) subscribeNewHeadsForEthereByCall(client *ethClient) error {
	debug("relay.subscribeNewHeadsForEthereByCall.start chainID=%d", client.chainID)

	var (
		ctx   = context.Background()
		start = now()
	)

	var waiters = make(map[common.Address]PaymentWaiter)

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, coinsTotal
	FROM payments
	WHERE orderPayedAt IS NULL
		AND erc20TokenAddr IS NULL -- see watchErc20Payments()
		AND orderFinalizedAt >= NOW() - INTERVAL '1 day'
        AND chainId = $1
 ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry, client.chainID)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.purchaseAddr, &waiter.coinsTotal)
		check(err)

		waiters[waiter.purchaseAddr] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.subscribeNewHeadsForEthereByCall.noOpenPayments took=%d", took(start))
		return nil
	}

	debug("relay.subscribeNewHeadsForEthereByCall.dbRead took=%d waiters=%d", took(start), len(waiters))

	rpc, err := client.getWebsocketRPC()
	if err != nil {
		return err
	}

	ch := make(chan *types.Header)
	sub, err := rpc.SubscribeNewHead(ctx, ch)
	if err != nil {
		return fmt.Errorf("subNewHead failed: %w", err)
	}
	defer sub.Unsubscribe()
	errch := sub.Err()

	select {
	case err := <-errch:
		return fmt.Errorf("subscription broke: %w", err)

	case newHead := <-ch:
		for addr, waiter := range waiters {
			balance, err := rpc.BalanceAt(ctx, addr, newHead.Number)
			if err != nil {
				return fmt.Errorf("relay.subscribeNewHeadsForEthereByCall.balanceAtFailed addr=%s block=%s err=%w", addr.Hex(), newHead.Number.String(), err)
			}

			if balance.Cmp(&waiter.coinsTotal.Int) == -1 {
				continue
			}

			debug("relay.subscribeNewHeadsForEthereByCall.checkTx checkingBlock=%s to=%s", newHead.Hash().Hex(), addr.Hex())
			orderID := waiter.orderID
			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			op := PaymentFoundInternalOp{
				orderID: orderID,
				txHash:  newHead.Hash(),
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // wait for write

			delete(waiters, waiter.purchaseAddr)
			log("relay.subscribeNewHeadsForEthereByCall.completed orderId=%s", orderID)
		}
	}

	stillWaiting := len(waiters)
	debug("relay.subscribeNewHeadsForEthereByCall.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_eth_open", uint64(stillWaiting))
	return nil
}

func (r *Relay) subscribeFilterLogsERC20Transfers(geth *ethClient) error {
	debug("relay.subscribeFilterLogsERC20Transfers.start chainID=%d", geth.chainID)

	var (
		start = now()
		ctx   = r.watcherContextERC20

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters         = make(map[common.Hash]PaymentWaiter)
		erc20AddressSet = make(map[common.Address]struct{})
	)

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr
		FROM payments
		WHERE orderPayedAt IS NULL
			AND erc20TokenAddr IS NOT NULL -- see subscribeFilterLogsERC20Transfers()
			AND orderFinalizedAt >= NOW() - INTERVAL '1 day'
            AND chainId = $1
ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry, geth.chainID)
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
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.subscribeFilterLogsERC20Transfers.noOpenPayments took=%d", took(start))
		time.Sleep(ethereumBlockInterval)
		return nil
	}

	rpc, err := geth.getWebsocketRPC()
	if err != nil {
		return err
	}

	currentBlockNo, err := rpc.BlockNumber(ctx)
	if err != nil {
		return err
	}
	debug("relay.subscribeFilterLogsERC20Transfers.starting currentBlock=%d", currentBlockNo)

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
		return fmt.Errorf("relay.subscribeFilterLogsERC20Transfers.EthSubscribeFailed: %w", err)
	}
	defer subscription.Unsubscribe()

	errch := subscription.Err()
	i = 0
	var lastBlockNo uint64

watch:
	for {
		select {
		case <-ctx.Done():
			break watch
		case err := <-errch:
			debug("relay.subscribeFilterLogsERC20Transfers err=%s", err)
			break watch
		case vLog := <-ch:
			log("relay.subscribeFilterLogsERC20Transfers i=%d block_tx=%s", i, vLog.BlockHash.Hex())
			i++
			// debug("relay.subscribeFilterLogsERC20Transfers.checking block=%d", vLog.BlockNumber)
			debug("relay.subscribeFilterLogsERC20Transfers.checking topics=%#v", vLog.Topics[1:])
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
					log("relay.subscribeFilterLogsERC20Transfers.transferErc20.failedToUnpackTransfer tx=%s err=%s", vLog.TxHash.Hex(), err)
					continue
				}

				inTx, ok := evts[0].(*big.Int)
				assertWithMessage(ok, fmt.Sprintf("unexpected unpack result for field 0 - type=%T", evts[0]))
				debug("relay.subscribeFilterLogsERC20Transfers.foundTransfer orderId=%s from=%s to=%s amount=%s", orderID, fromHash.Hex(), toHash.Hex(), inTx.String())

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
					log("relay.subscribeFilterLogsERC20Transfers.completed orderId=%s", orderID)

				} else {
					// it is still smaller
					log("relay.subscribeFilterLogsERC20Transfers.partial orderId=%s inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
					_, err = r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
					check(err)
				}
			} else {
				log("relay.subscribeFilterLogsERC20Transfers.noWaiter inTx=%s", vLog.TxHash.Hex())
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
			debug("relay.subscribeFilterLogsERC20Transfers.advance orderId=%x newLastBlock=%s", waiter.orderID, waiter.lastBlockNo.String())
		}
	}
	stillWaiting := len(waiters)
	debug("relay.subscribeFilterLogsERC20Transfers.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_erc20_open", uint64(stillWaiting))
	return nil
}
