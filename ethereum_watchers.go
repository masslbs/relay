// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
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
)

func (r *Relay) subscriptPaymentsMade(geth *ethClient) error {
	log("relay.subscriptPaymentsMade.start chainID=%d", geth.chainID)

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

func (r *Relay) watchEthereumPayments(client *ethClient) error {
	debug("relay.watchEthereumPayments.start chainID=%d", client.chainID)

	var (
		ctx   = context.Background()
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Address]PaymentWaiter)
	)

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
		if waiter.lastBlockNo.Cmp(lowestLastBlock) == -1 {
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

	rpc, err := client.getWebsocketRPC()
	if err != nil {
		return err
	}

	// Get the latest block number
	currentBlockNoInt, err := rpc.BlockNumber(ctx)
	check(err)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	for {
		if currentBlockNo.Cmp(lowestLastBlock) == -1 {
			// nothing to do
			debug("relay.watchEthereumPayments.noNewBlocks current=%d", currentBlockNoInt)
			break
		}
		debug("relay.watchEthereumPayments.checkBlock num=%d", lowestLastBlock)

		// check each block for transactions
		block, err := rpc.BlockByNumber(ctx, lowestLastBlock)
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

		// increment iterator
		lowestLastBlock.Add(lowestLastBlock, bigOne)
	}

	// update waiters in db
	var orderIDs []eventID
	for _, waiter := range waiters {
		// only advance those waiters which last blocks are lower then the block we just checked
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == 1 {
			continue
		}
		orderIDs = append(orderIDs, waiter.orderID)
	}
	if len(orderIDs) > 0 {
		// batch the update
		const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE orderId = any($1);`
		_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, orderIDs, lowestLastBlock.String())
		check(err)
		debug("relay.watchEthereumPayments.advance orderIds=%v newLastBlock=%s", orderIDs, lowestLastBlock.String())
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

func (r *Relay) watchErc20Payments(geth *ethClient) error {
	debug("relay.watchErc20Payments.start chainID=%d", geth.chainID)

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
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.watchErc20Payments.noOpenPayments took=%d", took(start))
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
	debug("relay.watchErc20Payments.starting currentBlock=%d", currentBlockNo)

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
		return fmt.Errorf("relay.watchErc20Payments.EthSubscribeFailed: %w", err)
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
			debug("relay.watchErc20Payments err=%s", err)
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

func (r *Relay) watchPaymentMade(geth *ethClient) error {
	debug("relay.watchPaymentMade.start chainID=%d", geth.chainID)

	var (
		ctx   = context.Background()
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Hash]PaymentWaiter)
	)

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
		pid := common.Hash(waiter.paymentId)
		//debug("relay.watchPaymentMade.want pid=%s", pid.Hex())
		waiters[pid] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		debug("relay.watchPaymentMade.noOpenPayments took=%d", took(start))
		return nil
	}

	gethClient, err := geth.getWebsocketRPC()
	if err != nil {
		return err
	}

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
