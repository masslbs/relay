// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/url"
	"os"
	reflect "reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	anypb "google.golang.org/protobuf/types/known/anypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// EventState represents the state of an event in the database.
type EventState struct {
	seq   uint64
	acked bool

	encodedEvent SignedEvent
}

// SessionState represents the state of a client in the database.
type SessionState struct {
	version           uint
	authChallenge     []byte
	sessionOps        chan SessionOp
	keyCardID         keyCardID
	keyCardPublicKey  []byte
	keyCardOfAGuest   bool
	shopID            ObjectIDArray
	lastSeenAt        time.Time
	lastSeenAtFlushed time.Time
	subscriptions     map[uint16]*SubscriptionState
}

// SubscriptionState represents the state of a subscription for a client
type SubscriptionState struct {
	shopID              ObjectIDArray
	buffer              []*EventState
	initialStatus       bool
	lastStatusedSeq     uint64
	lastBufferedSeq     uint64
	lastPushedSeq       uint64
	nextPushIndex       int
	lastAckedSeq        uint64
	lastAckedSeqFlushed uint64
	whereFragment       string
}

// CachedMetadata represents data cached which is common to all events
type CachedMetadata struct {
	objectID                *ObjectIDArray
	createdByShopID         ObjectIDArray
	createdByKeyCardID      keyCardID
	createdByNetworkVersion uint16
	serverSeq               uint64
	shopSeq                 uint64

	// helper fields
	writtenByRelay bool
}

func newMetadata(keyCardID keyCardID, shopID ObjectIDArray, version uint16) CachedMetadata {
	var metadata CachedMetadata
	assert(keyCardID != 0)
	metadata.createdByKeyCardID = keyCardID
	metadata.createdByShopID = shopID
	metadata.createdByNetworkVersion = version
	return metadata
}

// TODO: move

// comparable type, usable for map keys
type cachedShopCurrency struct {
	Addr    common.Address
	ChainID uint64
}

func (sc *ShopCurrency) cached() cachedShopCurrency {
	assert(sc.Address != nil && sc.Address.validate("") == nil)
	assert(sc.ChainId != 0)
	return cachedShopCurrency{
		Addr:    common.Address(sc.Address.Raw),
		ChainID: sc.ChainId,
	}
}

func (a cachedShopCurrency) Equal(b cachedShopCurrency) bool {
	return a.ChainID == b.ChainID && a.Addr.Cmp(b.Addr) == 0
}

type cachedCurrenciesMap map[cachedShopCurrency]struct{}

// </move>

// CachedShopManifest is latest reduction of a ShopManifest.
// It combines the intial ShopManifest and all UpdateShopManifests
type CachedShopManifest struct {
	CachedMetadata
	init sync.Once

	shopTokenID        []byte
	payees             map[string]*Payee
	acceptedCurrencies cachedCurrenciesMap
	pricingCurrency    cachedShopCurrency
	shippingRegions    map[string]*ShippingRegion
	orderModifiers     map[ObjectIDArray]*OrderPriceModifier
}

func (current *CachedShopManifest) update(union *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.acceptedCurrencies = make(cachedCurrenciesMap)
		current.payees = make(map[string]*Payee)
		current.shippingRegions = make(map[string]*ShippingRegion)
		current.orderModifiers = make(map[ObjectIDArray]*OrderPriceModifier)
	})
	switch union.Union.(type) {
	case *ShopEvent_Manifest:
		sm := union.GetManifest()
		current.CachedMetadata = meta
		current.shopTokenID = sm.TokenId.Raw
		for _, add := range sm.AcceptedCurrencies {
			current.acceptedCurrencies[cachedShopCurrency{
				common.Address(add.Address.Raw),
				add.ChainId,
			}] = struct{}{}
		}
		for _, payee := range sm.Payees {
			_, has := current.payees[payee.Name]
			assert(!has)
			current.payees[payee.Name] = payee
		}
		current.pricingCurrency = cachedShopCurrency{
			common.Address(sm.PricingCurrency.Address.Raw),
			sm.PricingCurrency.ChainId,
		}
		for _, region := range sm.ShippingRegions {
			current.shippingRegions[region.Name] = region
		}
	case *ShopEvent_UpdateManifest:
		um := union.GetUpdateManifest()
		if adds := um.AddAcceptedCurrencies; len(adds) > 0 {
			for _, add := range adds {
				c := cachedShopCurrency{
					common.Address(add.Address.Raw),
					add.ChainId,
				}
				current.acceptedCurrencies[c] = struct{}{}
			}
		}
		if rms := um.RemoveAcceptedCurrencies; len(rms) > 0 {
			for _, rm := range rms {
				c := cachedShopCurrency{
					common.Address(rm.Address.Raw),
					rm.ChainId,
				}
				delete(current.acceptedCurrencies, c)
			}
		}
		if bc := um.SetPricingCurrency; bc != nil {
			current.pricingCurrency = cachedShopCurrency{
				Addr:    common.Address(bc.Address.Raw),
				ChainID: bc.ChainId,
			}
		}
		if p := um.AddPayee; p != nil {
			_, taken := current.payees[p.Name]
			assert(!taken)
			current.payees[p.Name] = p
		}
		if p := um.RemovePayee; p != nil {
			delete(current.payees, p.Name)
		}
		for _, add := range um.AddShippingRegions {
			current.shippingRegions[add.Name] = add
		}
		for _, rm := range um.RemoveShippingRegions {
			delete(current.shippingRegions, rm)
		}
	}
}

// CachedListing is the latest reduction of an Item.
// It combines the initial CreateItem and all UpdateItems
type CachedListing struct {
	CachedMetadata
	init sync.Once

	value *Listing

	// utility map
	// optionID:variationID
	options map[ObjectIDArray]map[ObjectIDArray]*ListingVariation
}

func (current *CachedListing) update(union *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.options = make(map[ObjectIDArray]map[ObjectIDArray]*ListingVariation)

	})
	switch tv := union.Union.(type) {
	case *ShopEvent_Listing:
		current.CachedMetadata = meta
		current.value = tv.Listing
	case *ShopEvent_UpdateListing:
		current.CachedMetadata = meta
		ui := tv.UpdateListing
		if p := ui.Price; p != nil {
			current.value.Price = p
		}
		if meta := ui.Metadata; meta != nil {
			if t := meta.Title; t != "" {
				current.value.Metadata.Title = t
			}
			if d := meta.Description; d != "" {
				current.value.Metadata.Description = d
			}
			if i := meta.Images; i != nil {
				current.value.Metadata.Images = i
			}
		}
		// TODO: the stuff below here is a pile of poo. we shouldn't reduce the amount of duplication here
		for _, add := range ui.AddOptions {
			_, has := current.options[add.Id.Array()]
			assert(!has)
			newOpt := make(map[ObjectIDArray]*ListingVariation, len(add.Variations))
			for _, variation := range add.Variations {
				newOpt[variation.Id.Array()] = variation
			}
			current.options[add.Id.Array()] = newOpt
			current.value.Options = append(current.value.Options, add)
		}
		for _, rm := range ui.RemoveOptionIds {
			_, has := current.options[rm.Array()]
			assert(has)
			delete(current.options, rm.Array())
			found := -1
			opts := current.value.Options
			for idx, opt := range opts {
				if opt.Id.Equal(rm) {
					found = idx
					break
				}
			}
			assert(found != -1)
			opts = append(opts[:found], opts[found+1:]...)
			current.value.Options = opts
		}
		for _, add := range ui.AddVariations {
			opt, has := current.options[add.OptionId.Array()]
			assert(has)
			opt[add.Variation.Id.Array()] = add.Variation
			found := -1
			opts := current.value.Options
			for idx, opt := range opts {
				if opt.Id.Equal(add.OptionId) {
					found = idx
					break
				}
			}
			assert(found != -1)
			opts[found].Variations = append(opts[found].Variations, add.Variation)
		}
		for _, rm := range ui.RemoveVariationIds {
			for _, vars := range current.options {
				_, has := vars[rm.Array()]
				if has {
					delete(vars, rm.Array())
				}
			}
			found := [2]int{-1, -1}
			opts := current.value.Options
			for idxOpt, opt := range opts {
				for idxVar, variation := range opt.Variations {
					if variation.Id.Equal(rm) {
						found[0] = idxOpt
						found[1] = idxVar
						break
					}
				}
			}
			assert(found[0] != -1)
			foundVars := opts[found[0]].Variations
			foundVars = append(foundVars[:found[1]], foundVars[found[1]+1:]...)
			opts[found[0]].Variations = foundVars
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", union.Union))
	}
}

// CachedTag is the latest reduction of a Tag.
// It combines the initial CreateTag and all AddToTag, RemoveFromTag, RenameTag, and DeleteTag
type CachedTag struct {
	CachedMetadata
	init sync.Once

	tagID   ObjectIDArray
	name    string
	deleted bool
	items   *SetInts[uint64]
}

func (current *CachedTag) update(evt *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.items = NewSetInts[uint64]()
	})
	switch evt.Union.(type) {
	case *ShopEvent_Tag:
		current.CachedMetadata = meta
		ct := evt.GetTag()
		current.name = ct.Name
		current.tagID = ct.Id.Array()
	case *ShopEvent_UpdateTag:
		ut := evt.GetUpdateTag()
		for _, id := range ut.AddListingIds {
			current.items.Add(id.Uint64())
		}
		for _, id := range ut.RemoveListingIds {
			current.items.Delete(id.Uint64())
		}
		if r := ut.Rename; r != nil {
			current.name = *r
		}
		if d := ut.Delete; d != nil && *d {
			current.deleted = true
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))
	}
}

// CachedOrder is the latest reduction of a Order.
// It combines the initial CreateOrder and all ChangeOrder events
type CachedOrder struct {
	CachedMetadata
	init sync.Once

	order Order

	paymentID []byte
	items     *MapInts[combinedID, uint32]
}

func (current *CachedOrder) update(evt *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.items = NewMapInts[combinedID, uint32]()
	})
	switch msg := evt.Union.(type) {
	case *ShopEvent_CreateOrder:
		ct := msg.CreateOrder
		current.CachedMetadata = meta
		current.order.Id = ct.Id
	case *ShopEvent_UpdateOrder:
		uo := msg.UpdateOrder
		switch action := uo.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			ci := action.ChangeItems
			for _, id := range ci.Adds {
				sid := newCombinedID(id.ListingId, id.VariationIds...)
				count := current.items.Get(sid)
				count += id.Quantity
				current.items.Set(sid, count)
			}
			for _, id := range ci.Removes {
				sid := newCombinedID(id.ListingId, id.VariationIds...)
				count := current.items.Get(sid)
				if id.Quantity > count {
					count = 0
				} else {
					count -= id.Quantity
				}
				current.items.Set(sid, count)
			}
		case *UpdateOrder_CommitItems_:
			current.order.CommitedAt = evt.Timestamp
		case *UpdateOrder_SetInvoiceAddress:
			current.order.InvoiceAddress = action.SetInvoiceAddress
			current.order.AddressUpdatedAt = evt.Timestamp
		case *UpdateOrder_SetShippingAddress:
			current.order.ShippingAddress = action.SetShippingAddress
			current.order.AddressUpdatedAt = evt.Timestamp
		case *UpdateOrder_SetPaymentDetails:
			fin := action.SetPaymentDetails
			current.paymentID = fin.PaymentId.Raw
			current.order.PaymentDetailsCreatedAt = evt.Timestamp
		case *UpdateOrder_Cancel_:
			current.order.CanceledAt = evt.Timestamp
		case *UpdateOrder_AddPaymentTx:
			current.order.PaymentTransactions = append(current.order.PaymentTransactions, action.AddPaymentTx)
		case *UpdateOrder_SetShippingStatus:
			current.order.ShippingStatus = action.SetShippingStatus
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))

	}
}

// CachedStock represents the latest reduction of a Shop's stock.
// It combines all ChangeStock events.
type CachedStock struct {
	CachedMetadata

	init sync.Once

	inventory *MapInts[combinedID, int32]
}

func (current *CachedStock) update(evt *ShopEvent, _ CachedMetadata) {
	cs := evt.GetChangeInventory()
	if cs == nil {
		return
	}
	current.init.Do(func() {
		current.inventory = NewMapInts[combinedID, int32]()
	})
	cid := newCombinedID(cs.Id, cs.VariationIds...)
	stock := current.inventory.Get(cid)
	stock += cs.Diff
	current.inventory.Set(cid, stock)
}

// CachedEvent is the interface for all cached events
type CachedEvent interface {
	comparable
	update(*ShopEvent, CachedMetadata)
}

// ShopState helps with writing events to the database
type ShopState struct {
	lastUsedSeq    uint64
	lastWrittenSeq uint64

	relayKeyCardID             keyCardID
	lastWrittenRelayEventNonce uint64
	shopTokenID                Uint256
}

func (ss *ShopState) nextRelayEventNonce() uint64 {
	next := ss.lastWrittenRelayEventNonce + 1
	ss.lastWrittenRelayEventNonce = next
	return next
}

// IO represents the input/output of the server.
type IO struct {
	metric *Metric

	connPool *pgxpool.Pool
	ethereum *ethRPCService

	prices priceConverter
}

// Relay is the main server struct and represents the database layer
type Relay struct {
	writesEnabled bool // ensures to only create new events if set to true

	IO
	sessionIDsToSessionStates *MapInts[sessionID, *SessionState]
	opsInternal               chan RelayOp
	ops                       chan RelayOp

	blobUploadTokens   map[string]struct{}
	blobUploadTokensMu *sync.Mutex

	baseURL *url.URL

	// persistence
	syncTx               pgx.Tx
	queuedEventInserts   []*EventInsert
	shopIDsToShopState   *MapInts[ObjectIDArray, *ShopState] // Changed from shopIdsToShopState
	lastUsedServerSeq    uint64
	lastWrittenServerSeq uint64

	// caching layer
	shopManifestsByShopID *ReductionLoader[*CachedShopManifest]
	listingsByListingID   *ReductionLoader[*CachedListing]
	stockByShopID         *ReductionLoader[*CachedStock]
	tagsByTagID           *ReductionLoader[*CachedTag]
	ordersByOrderID       *ReductionLoader[*CachedOrder]
	allLoaders            []Loader

	connectionLimiter *rate.Limiter
	connectionCount   atomic.Int64
	maxConnections    int64
}

func newRelay(metric *Metric) *Relay {
	r := &Relay{}

	var err error
	r.baseURL, err = url.Parse(mustGetEnvString("RELAY_BASE_URL"))
	check(err)

	r.ethereum = newEthRPCService(nil)

	if cgAPIKey := os.Getenv("COINGECKO_API_KEY"); cgAPIKey != "" {
		r.prices = newCoinGecko(cgAPIKey, "usd", r.ethereum)
	} else {
		r.prices = testingConverter{}
	}

	r.sessionIDsToSessionStates = NewMapInts[sessionID, *SessionState]()
	r.opsInternal = make(chan RelayOp)
	r.ops = make(chan RelayOp, databaseOpsChanSize)
	r.shopIDsToShopState = NewMapInts[ObjectIDArray, *ShopState]()

	shopFieldFn := func(_ *ShopEvent, meta CachedMetadata) (ShopObjectIDArray, bool) {
		return newShopObjectID(meta.createdByShopID, meta.createdByShopID), true
	}
	r.shopManifestsByShopID = newReductionLoader[*CachedShopManifest](r, shopFieldFn, []eventType{
		eventTypeManifest,
		eventTypeUpdateManifest,
		eventTypeAccount,
	}, "createdByShopId")
	r.stockByShopID = newReductionLoader[*CachedStock](r, shopFieldFn, []eventType{eventTypeChangeInventory}, "createdByShopId")

	itemsFieldFn := func(evt *ShopEvent, meta CachedMetadata) (ShopObjectIDArray, bool) {
		switch tv := evt.Union.(type) {
		case *ShopEvent_Listing:
			return newShopObjectID(meta.createdByShopID, tv.Listing.Id.Array()), true
		case *ShopEvent_UpdateListing:
			return newShopObjectID(meta.createdByShopID, tv.UpdateListing.Id.Array()), true
		}
		return ShopObjectIDArray{}, false
	}
	r.listingsByListingID = newReductionLoader[*CachedListing](r, itemsFieldFn, []eventType{
		eventTypeListing,
		eventTypeUpdateListing,
	}, "objectID")

	tagsFieldFn := func(evt *ShopEvent, meta CachedMetadata) (ShopObjectIDArray, bool) {
		switch tv := evt.Union.(type) {
		case *ShopEvent_Tag:
			return newShopObjectID(meta.createdByShopID, tv.Tag.Id.Array()), true
		case *ShopEvent_UpdateTag:
			return newShopObjectID(meta.createdByShopID, tv.UpdateTag.Id.Array()), true
		}
		return ShopObjectIDArray{}, false
	}
	r.tagsByTagID = newReductionLoader[*CachedTag](r, tagsFieldFn, []eventType{
		eventTypeTag,
		eventTypeUpdateTag,
	}, "objectID")

	ordersFieldFn := func(evt *ShopEvent, meta CachedMetadata) (ShopObjectIDArray, bool) {
		switch tv := evt.Union.(type) {
		case *ShopEvent_CreateOrder:
			return newShopObjectID(meta.createdByShopID, tv.CreateOrder.Id.Array()), true
		case *ShopEvent_UpdateOrder:
			return newShopObjectID(meta.createdByShopID, tv.UpdateOrder.Id.Array()), true
		}

		return ShopObjectIDArray{}, false
	}
	r.ordersByOrderID = newReductionLoader[*CachedOrder](r, ordersFieldFn, []eventType{
		eventTypeCreateOrder,
		eventTypeUpdateOrder,
	}, "objectID")

	r.blobUploadTokens = make(map[string]struct{})
	r.blobUploadTokensMu = &sync.Mutex{}

	r.metric = metric

	// Initialize rate limiter: 10 new connections per second, burst of 50
	r.connectionLimiter = rate.NewLimiter(rate.Limit(10), 50)
	r.maxConnections = 256 // Default max connections

	return r
}

func (r *Relay) connect() {
	log("relay.pg.connect")
	r.connPool = newPool()

	r.loadServerSeq()
}

// TODO: generics solution to reduce [][]any copies
// Returns two slices: rows inserted, and rows not inserted due to conflicts.
func (r *Relay) bulkInsert(table string, columns []string, rows [][]interface{}) ([][]interface{}, [][]interface{}) {
	assertNonemptyString(table)
	assert(len(columns) > 0)
	assert(len(rows) > 0)
	start := now()
	ctx := context.Background()
	qb := strings.Builder{}
	qb.WriteString("insert into ")
	qb.WriteString(table)
	qb.WriteString(" (")
	for c := 0; c < len(columns); c++ {
		qb.WriteString(columns[c])
		if c < len(columns)-1 {
			qb.WriteString(",")
		}
	}
	qb.WriteString(") values (")
	for v := 1; v <= len(columns); v++ {
		qb.WriteString(fmt.Sprintf("$%d", v))
		if v < len(columns) {
			qb.WriteString(",")
		}
	}
	qb.WriteString(") on conflict do nothing")
	q := qb.String()
	insertedRows := make([][]interface{}, 0)
	conflictingRows := make([][]interface{}, 0)
	var tx pgx.Tx
	var err error
	if r.syncTx != nil {
		tx = r.syncTx
	} else {
		tx, err = r.connPool.Begin(ctx)
		defer func() {
			_ = tx.Rollback(ctx)
		}()
		check(err)
	}

	batch := &pgx.Batch{}
	for r := 0; r < len(rows); r++ {
		batch.Queue(q, rows[r]...)
	}
	br := tx.SendBatch(ctx, batch)
	for r := 0; r < len(rows); r++ {
		ct, err := br.Exec()
		if err != nil {
			fmt.Println("[DEBUG/bulkInsertFail]")
			fmt.Println("row:", rows[r], len(rows[r]))
			fmt.Println("cols:", columns, len(columns))
			check(err)
		}
		rowsAffected := ct.RowsAffected()
		if rowsAffected == 1 {
			insertedRows = append(insertedRows, rows[r])
		} else if rowsAffected == 0 {
			conflictingRows = append(conflictingRows, rows[r])
		} else {
			panic(fmt.Errorf("unexpected rowsAffected=%d", rowsAffected))
		}
	}
	check(br.Close())
	if r.syncTx == nil {
		check(tx.Commit(ctx))
	}
	debug("relay.bulkInsert table=%s columns=%d rows=%d insertedRows=%d conflictingRows=%d elapsed=%d", table, len(columns), len(rows), len(insertedRows), len(conflictingRows), took(start))
	return insertedRows, conflictingRows
}

func (r *Relay) assertCursors(sid sessionID, shopState *ShopState, state *SubscriptionState) {
	err := r.checkCursors(sid, shopState, state)
	check(err)
}

func (r *Relay) checkCursors(sid sessionID, shopState *ShopState, state *SubscriptionState) error {
	if shopState.lastUsedSeq < shopState.lastWrittenSeq {
		return fmt.Errorf("cursor[%d]: lastUsedShopSeq(%d) < lastWrittenShopSeq(%d)", sid, shopState.lastUsedSeq, shopState.lastWrittenSeq)
	}
	if shopState.lastWrittenSeq < state.lastStatusedSeq {
		return fmt.Errorf("cursor[%d]: lastWrittenSeq(%d) < lastStatusedSeq(%d)", sid, shopState.lastWrittenSeq, state.lastStatusedSeq)
	}
	if state.lastStatusedSeq < state.lastBufferedSeq {
		return fmt.Errorf("cursor[%d]: lastStatusedSeq(%d) < lastBufferedSeq(%d)", sid, state.lastStatusedSeq, state.lastBufferedSeq)
	}
	if state.lastBufferedSeq < state.lastPushedSeq {
		return fmt.Errorf("cursor[%d]: lastBufferedSeq(%d) < lastPushedSeq(%d)", sid, state.lastBufferedSeq, state.lastPushedSeq)
	}
	if state.lastPushedSeq < state.lastAckedSeq {
		return fmt.Errorf("cursor[%d]: lastPushedSeq(%d) < lastAckedSeq(%d)", sid, state.lastPushedSeq, state.lastAckedSeq)
	}
	return nil
}

func (r *Relay) sendSessionOp(sessionState *SessionState, op SessionOp) {
	select {
	case sessionState.sessionOps <- op:
	default:
		panic(fmt.Errorf("relay.sendSessionOp.blocked keyCardId=%d %+v", sessionState.keyCardID, op))
	}
}

func (r *Relay) lastSeenAtTouch(sessionState *SessionState) time.Time {
	n := now()
	sessionState.lastSeenAt = n
	return n
}

// used during keycard enroll. creates the keycard
// only use this inside transactions
func (r *Relay) getOrCreateInternalShopID(shopTokenID big.Int) (ObjectIDArray, uint64) {
	var (
		err       error
		dbID      uint64
		shopID    ObjectIDArray
		relayKCID keyCardID
		ctx       = context.Background()
	)
	assert(r.syncTx != nil)
	tx := r.syncTx

	err = tx.QueryRow(ctx, `select id from shops where tokenId = $1`, shopTokenID.String()).Scan(&dbID)
	if err == nil {
		binary.BigEndian.PutUint64(shopID[:], dbID)
		return shopID, dbID
	} else if err != pgx.ErrNoRows {
		check(err)
	}

	const qryInsertShop = `insert into shops (tokenId, createdAt) values ($1, now()) returning id`
	err = tx.QueryRow(ctx, qryInsertShop, shopTokenID.String()).Scan(&dbID)
	check(err)
	binary.BigEndian.PutUint64(shopID[:], dbID)

	const qryInsertRelayKeyCard = `insert into relayKeyCards (cardPublicKey, shopId, lastUsedAt, lastWrittenEventNonce) values ($1, $2, now(), 0) returning id`
	err = tx.QueryRow(ctx, qryInsertRelayKeyCard, r.ethereum.keyPair.CompressedPubKey(), dbID).Scan(&relayKCID)
	check(err)

	// the hydrate call in enrollKeyCard will not be able to read/select the above insert
	assert(!r.shopIDsToShopState.Has(shopID))
	r.shopIDsToShopState.Set(shopID, &ShopState{
		relayKeyCardID: relayKCID,
	})

	return shopID, dbID
}

func (r *Relay) hydrateShops(shopIDs *SetInts[ObjectIDArray]) {
	start := now()
	ctx := context.Background()
	novelShopIDs := NewSetInts[ObjectIDArray]()
	shopIDs.All(func(sid ObjectIDArray) bool {
		if !r.shopIDsToShopState.Has(sid) {
			novelShopIDs.Add(sid)
		}
		return false
	})
	if sz := novelShopIDs.Size(); sz > 0 {
		novelShopIDs.All(func(shopID ObjectIDArray) bool {
			shopState := &ShopState{}
			r.shopIDsToShopState.Set(shopID, shopState)
			return false
		})
		novelIDArrays := novelShopIDs.Slice()
		arraysToSlices := make([][]byte, len(novelIDArrays))
		for i, arr := range novelIDArrays {
			arraysToSlices[i] = arr[:]
		}
		for _, novelShopIDsSubslice := range subslice(arraysToSlices, 256) {
			// Index: events(createdByShopId, shopSeq)
			const queryLatestShopSeq = `select createdByShopId, max(shopSeq) from events where createdByShopId = any($1) group by createdByShopId`
			rows, err := r.connPool.Query(ctx, queryLatestShopSeq, novelShopIDsSubslice)
			check(err)
			for rows.Next() {
				var dbID uint64
				var lastWrittenSeq *uint64
				err = rows.Scan(&dbID, &lastWrittenSeq)
				check(err)
				var shopID ObjectIDArray
				binary.BigEndian.PutUint64(shopID[:], dbID)
				shopState := r.shopIDsToShopState.MustGet(shopID)
				if lastWrittenSeq != nil {
					shopState.lastWrittenSeq = *lastWrittenSeq
					shopState.lastUsedSeq = *lastWrittenSeq
				}
			}
			check(rows.Err())
			rows.Close()

			const queryLastRelayNonce = "select shopId, id, lastWrittenEventNonce from relayKeyCards where shopId = any($1)"
			rows, err = r.connPool.Query(ctx, queryLastRelayNonce, novelShopIDsSubslice)
			check(err)
			for rows.Next() {
				var dbID uint64
				var relayKCID keyCardID
				var relayNonce uint64
				err = rows.Scan(&dbID, &relayKCID, &relayNonce)
				check(err)
				var shopID ObjectIDArray
				binary.BigEndian.PutUint64(shopID[:], dbID)
				assert(relayKCID != 0)
				shopState := r.shopIDsToShopState.MustGet(shopID)
				shopState.lastWrittenRelayEventNonce = relayNonce
				shopState.relayKeyCardID = relayKCID
			}
			check(rows.Err())
			rows.Close()
		}
	}
	elapsed := took(start)
	if novelShopIDs.Size() > 0 || elapsed > 1 {
		log("relay.hydrateShops shops=%d novelShops=%d elapsed=%d", shopIDs.Size(), novelShopIDs.Size(), elapsed)
		r.metric.counterAdd("hydrate_users", float64(novelShopIDs.Size()))
	}
}

func (r *Relay) loadServerSeq() {
	log("relay.loadServerSeq.start")
	start := now()
	// Index: none
	err := r.connPool.QueryRow(context.Background(), `select serverSeq from events order by serverSeq desc limit 1`).Scan(&r.lastWrittenServerSeq)
	if err != nil {
		if err == pgx.ErrNoRows {
			r.lastWrittenServerSeq = 0
		} else {
			panic(err)
		}
	}
	r.lastUsedServerSeq = r.lastWrittenServerSeq
	log("relay.loadServerSeq.finish serverSeq=%d elapsed=%d", r.lastUsedServerSeq, took(start))
}

// readEvents from the database according to some
// `whereFragment` criteria, assumed to have a single `$1` arg for a
// slice of indexedIds.
// Does not change any in-memory caches; to be done by caller.
func (r *Relay) readEvents(whereFragment string, shopID, objectID ObjectIDArray) []EventInsert {
	// Index: events(field in whereFragment)
	// The indicies eventsOnEventTypeAnd* should correspond to the various Loaders defined in newDatabase.
	query := fmt.Sprintf(`select serverSeq, shopSeq, eventType, createdByKeyCardId, createdAt, createdByNetworkSchemaVersion, encoded
from events where createdByShopID = $1 and %s order by serverSeq asc`, whereFragment)
	var rows pgx.Rows
	var err error
	if r.syncTx != nil {
		rows, err = r.syncTx.Query(context.Background(), query, shopID[:], objectID[:])
	} else {
		rows, err = r.connPool.Query(context.Background(), query, shopID[:], objectID[:])
	}
	check(err)
	defer rows.Close()
	events := make([]EventInsert, 0)
	for rows.Next() {
		var (
			m         CachedMetadata
			eventType eventType
			createdAt time.Time
			encoded   []byte
		)
		err := rows.Scan(&m.serverSeq, &m.shopSeq, &eventType, &m.createdByKeyCardID, &createdAt, &m.createdByNetworkVersion, &encoded)
		check(err)
		m.createdByShopID = ObjectIDArray(shopID)
		m.objectID = &objectID
		var e ShopEvent
		err = proto.Unmarshal(encoded, &e)
		check(err)
		events = append(events, EventInsert{
			CachedMetadata: m,
			evt:            &e,
			evtType:        eventType,
		})
	}
	check(rows.Err())
	return events
}

// EventInsert is a struct that represents an event to be inserted into the database
type EventInsert struct {
	CachedMetadata
	evtType eventType
	evt     *ShopEvent
	pbany   *SignedEvent
}

func newEventInsert(evt *ShopEvent, meta CachedMetadata, abstract *SignedEvent) *EventInsert {
	return &EventInsert{
		CachedMetadata: meta,
		evt:            evt,
		pbany:          abstract,
	}
}

func (r *Relay) writeEvent(evt *ShopEvent, cm CachedMetadata, abstract *SignedEvent) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	shopSeqPair := r.shopIDsToShopState.MustGet(cm.createdByShopID)
	cm.shopSeq = shopSeqPair.lastUsedSeq + 1
	shopSeqPair.lastUsedSeq = cm.shopSeq

	insert := newEventInsert(evt, cm, abstract)
	r.queuedEventInserts = append(r.queuedEventInserts, insert)
	r.applyEvent(insert)
}

func (r *Relay) createRelayEvent(shopID ObjectIDArray, event isShopEvent_Union) {
	shopState := r.shopIDsToShopState.MustGet(shopID)
	evt := &ShopEvent{
		Nonce:     shopState.nextRelayEventNonce(),
		ShopId:    &shopState.shopTokenID,
		Timestamp: timestamppb.Now(),
		Union:     event,
	}

	var sigEvt SignedEvent
	var err error
	sigEvt.Event, err = anypb.New(evt)
	check(err)

	sigEvt.Signature, err = r.ethereum.signEvent(sigEvt.Event.Value)
	check(err)

	meta := newMetadata(shopState.relayKeyCardID, shopID, currentRelayVersion)
	meta.writtenByRelay = true
	r.writeEvent(evt, meta, &sigEvt)
}

func (r *Relay) beginSyncTransaction() {
	assert(r.queuedEventInserts == nil)
	assert(r.syncTx == nil)
	r.queuedEventInserts = make([]*EventInsert, 0)
	ctx := context.Background()
	tx, err := r.connPool.Begin(ctx)
	check(err)
	r.syncTx = tx
}

func (r *Relay) commitSyncTransaction() {
	assert(r.queuedEventInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	r.flushEvents()
	check(r.syncTx.Commit(ctx))
	r.queuedEventInserts = nil
	r.syncTx = nil
}

func (r *Relay) rollbackSyncTransaction() {
	assert(r.queuedEventInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	check(r.syncTx.Rollback(ctx))
	r.queuedEventInserts = nil
	r.syncTx = nil
}

var dbEventInsertColumns = []string{"eventType", "eventNonce", "createdByKeyCardId", "createdByShopId", "shopSeq", "createdAt", "createdByNetworkSchemaVersion", "serverSeq", "encoded", "signature", "objectID"}

func formInsert(ins *EventInsert) []interface{} {
	var (
		evtType = eventTypeInvalid
		objID   *[]byte // used to stich together related events
	)
	switch tv := ins.evt.Union.(type) {
	case *ShopEvent_Manifest:
		evtType = eventTypeManifest
	case *ShopEvent_UpdateManifest:
		evtType = eventTypeUpdateManifest
	case *ShopEvent_Listing:
		evtType = eventTypeListing
		arr := tv.Listing.Id.Raw
		objID = &arr
	case *ShopEvent_UpdateListing:
		evtType = eventTypeUpdateListing
		arr := tv.UpdateListing.Id.Raw
		objID = &arr
	case *ShopEvent_Tag:
		evtType = eventTypeTag
		arr := tv.Tag.Id.Raw
		objID = &arr
	case *ShopEvent_UpdateTag:
		evtType = eventTypeUpdateTag
		arr := tv.UpdateTag.Id.Raw
		objID = &arr
	case *ShopEvent_ChangeInventory:
		evtType = eventTypeChangeInventory
	case *ShopEvent_CreateOrder:
		evtType = eventTypeCreateOrder
		arr := tv.CreateOrder.Id.Raw
		objID = &arr
	case *ShopEvent_UpdateOrder:
		evtType = eventTypeUpdateOrder
		arr := tv.UpdateOrder.Id.Raw
		objID = &arr
	case *ShopEvent_Account:
		evtType = eventTypeAccount
	default:
		panic(fmt.Errorf("formInsert.unrecognizeType eventType=%T", ins.evt.Union))
	}
	assert(evtType != eventTypeInvalid)
	return []interface{}{
		evtType,                     // eventType
		ins.evt.Nonce,               // eventNonce
		ins.createdByKeyCardID,      // createdByKeyCardId
		ins.createdByShopID[:],      // createdByShopId
		ins.shopSeq,                 // shopSeq
		now(),                       // createdAt
		ins.createdByNetworkVersion, // createdByNetworkSchemaVersion
		ins.serverSeq,               // serverSeq
		ins.pbany.Event.Value,       // encoded
		ins.pbany.Signature.Raw,     // signature
		objID,                       // objectID
	}
}

func (r *Relay) flushEvents() {
	if len(r.queuedEventInserts) == 0 {
		return
	}
	assert(r.writesEnabled)
	log("relay.flushEvents.start entries=%d", len(r.queuedEventInserts))
	start := now()

	eventTuples := make([][]any, len(r.queuedEventInserts))
	relayEvents := make(map[keyCardID]uint64)
	for i, ei := range r.queuedEventInserts {
		eventTuples[i] = formInsert(ei)
		if ei.writtenByRelay {
			last := relayEvents[ei.createdByKeyCardID]
			if last < ei.evt.Nonce {
				relayEvents[ei.createdByKeyCardID] = ei.evt.Nonce
			}
		}
	}
	assert(r.lastWrittenServerSeq < r.lastUsedServerSeq)

	insertedEventRows, conflictedEventRows := r.bulkInsert("events", dbEventInsertColumns, eventTuples)
	for _, row := range insertedEventRows {
		rowServerSeq := row[7].(uint64)
		assert(r.lastWrittenServerSeq < rowServerSeq)
		assert(rowServerSeq <= r.lastUsedServerSeq)
		r.lastWrittenServerSeq = rowServerSeq
		rowShopID := row[3].([]byte)
		assert(len(rowShopID) == 8)
		rowShopSeq := row[4].(uint64)
		shopState := r.shopIDsToShopState.MustGet(ObjectIDArray(rowShopID))
		assert(shopState.lastWrittenSeq < rowShopSeq)
		assert(rowShopSeq <= shopState.lastUsedSeq)
		shopState.lastWrittenSeq = rowShopSeq
	}
	assert(r.lastWrittenServerSeq <= r.lastUsedServerSeq)
	r.queuedEventInserts = nil
	log("relay.flushEvents.events insertedEntries=%d conflictedEntries=%d", len(insertedEventRows), len(conflictedEventRows))

	ctx := context.Background()
	if len(relayEvents) > 0 {
		const updateRelayNonce = `UPDATE relayKeyCards set lastWrittenEventNonce=$2, lastUsedAt=now() where id = $1`
		// TODO: there must be nicer way to do this but i'm on a train right now
		// preferably building tuples and sending a single query but here we are...
		for kcID, lastNonce := range relayEvents {
			assert(kcID != 0)
			res, err := r.syncTx.Exec(ctx, updateRelayNonce, kcID, lastNonce)
			check(err)
			aff := res.RowsAffected()
			assertWithMessage(aff == 1, fmt.Sprintf("keyCards affected not 1 but %d", aff))
		}
	}

	log("relay.flushEvents.finish took=%d", took(start))
}

// Loader is an interface for all loaders.
// Loaders represent the read-through cache layer.
type Loader interface {
	applyEvent(*EventInsert)
}

type fieldFn func(*ShopEvent, CachedMetadata) (ShopObjectIDArray, bool)

// ReductionLoader is a struct that represents a loader for a specific event type
type ReductionLoader[T CachedEvent] struct {
	db            *Relay
	fieldFn       fieldFn
	loaded        *ShopEventMap[T]
	whereFragment string
}

func newReductionLoader[T CachedEvent](r *Relay, fn fieldFn, pgTypes []eventType, pgField string) *ReductionLoader[T] {
	sl := &ReductionLoader[T]{}
	sl.db = r
	sl.fieldFn = fn
	sl.loaded = NewShopEventMap[T]()
	var quotedTypes = make([]string, len(pgTypes))
	for i, pgType := range pgTypes {
		quotedTypes[i] = fmt.Sprintf("'%s'", string(pgType))
	}
	sl.whereFragment = fmt.Sprintf(`eventType IN (%s) and %s = $2`, strings.Join(quotedTypes, ","), pgField)
	r.allLoaders = append(r.allLoaders, sl)
	return sl
}

var zeroObjectIDArr [8]byte

func (sl *ReductionLoader[T]) applyEvent(e *EventInsert) {
	fieldID, has := sl.fieldFn(e.evt, e.CachedMetadata)
	if !has {
		return
	}
	v, has := sl.loaded.GetHas(fieldID)
	if has {
		v.update(e.evt, e.CachedMetadata)
	}
}

func (sl *ReductionLoader[T]) get(shopID ObjectIDArray, objectID ObjectIDArray) (T, bool) {
	var indexedID ShopObjectIDArray
	copy(indexedID[:8], shopID[:])
	copy(indexedID[8:], objectID[:])
	var zero T
	_, known := sl.loaded.GetHas(indexedID)
	if !known {
		entries := sl.db.readEvents(sl.whereFragment, shopID, objectID)
		n := len(entries)
		if n == 0 {
			return zero, false
		}
		var empty T
		typeOf := reflect.TypeOf(empty)
		var zeroValT = reflect.New(typeOf.Elem())
		var zeroVal = zeroValT.Interface().(T)
		sl.loaded.Set(indexedID, zeroVal)
		for _, e := range entries {
			sl.applyEvent(&e)
		}
		for _, qei := range sl.db.queuedEventInserts {
			sl.applyEvent(qei)
		}
	}
	all, has := sl.loaded.GetHas(indexedID)
	return all, has
}

func (r *Relay) applyEvent(e *EventInsert) {
	for _, loader := range r.allLoaders {
		loader.applyEvent(e)
	}
}

// Database processing

func (r *Relay) debounceSessions() {
	// Process each session.
	// Only log if there is substantial activity because this is polling constantly and usually a no-op.
	start := now()

	r.sessionIDsToSessionStates.All(func(sessionID sessionID, sessionState *SessionState) bool {
		// Kick the session if we haven't received any recent messages from it, including ping responses.
		if time.Since(sessionState.lastSeenAt) > sessionKickTimeout {
			r.metric.counterAdd("sessions_kick", 1)
			logS(sessionID, "relay.debounceSessions.kick")
			op := &StopOp{sessionID: sessionID}
			r.sendSessionOp(sessionState, op)
			return false
		}

		for subID, subscription := range sessionState.subscriptions {
			r.pushOutShopLog(sessionID, sessionState, subID, subscription)
		}

		return false
	})

	// Since we're polling this loop constantly, only log if takes a non-trivial amount of time.
	debounceTook := took(start)
	if debounceTook > 0 {
		r.metric.counterAdd("relay_debounceSessions_took", float64(debounceTook))
		log("relay.debounceSessions.finish sessions=%d elapsed=%d", r.sessionIDsToSessionStates.Size(), debounceTook)
	}
}

func (r *Relay) pushOutShopLog(sessionID sessionID, session *SessionState, subID uint16, sub *SubscriptionState) {
	ctx := context.Background()

	// If the session is authenticated, we can get user info.
	shopState := r.shopIDsToShopState.MustGet(sub.shopID)
	r.assertCursors(sessionID, shopState, sub)

	// Calculate the new keyCard seq up to which the device has acked all pushes.
	// Slice the buffer to drop such entries as they have completed their lifecycle.
	// Do this all first to trim down the buffer before reading more, if possible.
	var (
		advancedFrom uint64
		advancedTo   uint64
		i            = 0
	)
	for ; i < len(sub.buffer); i++ {
		entryState := sub.buffer[i]
		if !entryState.acked {
			break
		}
		assert(entryState.seq > sub.lastAckedSeq)
		if i == 0 {
			advancedFrom = sub.lastAckedSeq
		}
		sub.lastAckedSeq = entryState.seq
		advancedTo = entryState.seq
	}
	if i != 0 {
		sub.buffer = sub.buffer[i:]
		sub.nextPushIndex -= i
		logS(sessionID, "relay.debounceSessions.advanceSeq reason=entries from=%d to=%d", advancedFrom, advancedTo)
		r.assertCursors(sessionID, shopState, sub)
	}

	// Check if a sync status is needed, and if so query and send it.
	// Use the boolean to ensure we always send an initial sync status for the session,
	// including if the user has no writes yet.
	// If everything for the device has been pushed, advance the buffered and pushed cursors too.
	if !sub.initialStatus || sub.lastStatusedSeq < shopState.lastWrittenSeq {
		syncStatusStart := now()
		op := &SyncStatusOp{
			sessionID:      sessionID,
			subscriptionID: subID,
		}
		// Index: events(createdByShopId, shopSeq)
		query := `select count(*) from events
			where createdByShopId = $1 and shopSeq > $2
			  and (` + sub.whereFragment + `)`
		err := r.connPool.QueryRow(ctx, query, sub.shopID[:], sub.lastPushedSeq).
			Scan(&op.unpushedEvents)
		if err != pgx.ErrNoRows {
			check(err)
		}
		r.sendSessionOp(session, op)
		sub.initialStatus = true
		sub.lastStatusedSeq = shopState.lastWrittenSeq
		if op.unpushedEvents == 0 {
			sub.lastBufferedSeq = sub.lastStatusedSeq
			sub.lastPushedSeq = sub.lastStatusedSeq
		}
		logS(sessionID, "relay.debounceSessions.syncStatus initialStatus=%t unpushedEvents=%d elapsed=%d", sub.initialStatus, op.unpushedEvents, took(syncStatusStart))
		r.assertCursors(sessionID, shopState, sub)
	}

	// Check if more buffering is needed, and if so fill buffer.
	writesNotBuffered := sub.lastBufferedSeq < shopState.lastWrittenSeq
	var readsAllowed int
	if len(sub.buffer) >= sessionBufferSizeRefill {
		readsAllowed = 0
	} else {
		readsAllowed = sessionBufferSizeMax - len(sub.buffer)
	}
	if writesNotBuffered && readsAllowed > 0 {
		readStart := now()
		reads := 0
		// Index: events(shopId, shopSeq)
		query := `select e.shopSeq, e.encoded, e.signature
			from events e
			where e.createdByShopId = $1
			    and e.shopSeq > $2
				and (` + sub.whereFragment + `) order by e.shopSeq asc limit $3`
		rows, err := r.connPool.Query(ctx, query, sub.shopID[:], sub.lastPushedSeq, readsAllowed)
		check(err)
		defer rows.Close()
		for rows.Next() {
			var (
				eventState         = &EventState{}
				encoded, signature []byte
			)
			err := rows.Scan(&eventState.seq, &encoded, &signature)
			check(err)
			reads++
			// log("relay.debounceSessions.debug event=%x", eventState.eventID)

			eventState.acked = false
			sub.buffer = append(sub.buffer, eventState)
			assert(eventState.seq > sub.lastBufferedSeq)
			sub.lastBufferedSeq = eventState.seq

			// re-create pb object from encoded database data
			eventState.encodedEvent.Event = &anypb.Any{
				// TODO: would prever to not craft this manually
				TypeUrl: shopEventTypeURL,
				Value:   encoded,
			}
			eventState.encodedEvent.Signature = &Signature{Raw: signature}
		}
		check(rows.Err())

		// If the read rows didn't use the full limit, that means we must be at the end
		// of this user's writes.
		if reads < readsAllowed {
			sub.lastBufferedSeq = shopState.lastWrittenSeq
		}

		logS(sessionID, "relay.debounceSessions.read shopId=%x reads=%d readsAllowed=%d bufferLen=%d lastWrittenSeq=%d, lastBufferedSeq=%d elapsed=%d", sub.shopID, reads, readsAllowed, len(sub.buffer), shopState.lastWrittenSeq, sub.lastBufferedSeq, took(readStart))
		r.metric.counterAdd("relay_events_read", float64(reads))
	}
	r.assertCursors(sessionID, shopState, sub)

	// Push any events as needed.
	const maxPushes = limitMaxOutRequests * limitMaxOutBatchSize
	pushes := 0
	var eventPushOp *SubscriptionPushOp
	pushOps := make([]SessionOp, 0)
	for ; sub.nextPushIndex < len(sub.buffer) && sub.nextPushIndex < maxPushes; sub.nextPushIndex++ {
		entryState := sub.buffer[sub.nextPushIndex]
		if eventPushOp != nil && len(eventPushOp.eventStates) == limitMaxOutBatchSize {
			eventPushOp = nil
		}
		if eventPushOp == nil {
			eventPushOp = &SubscriptionPushOp{
				sessionID:      sessionID,
				subscriptionID: subID,
				eventStates:    make([]*EventState, 0),
			}
			pushOps = append(pushOps, eventPushOp)
		}
		eventPushOp.eventStates = append(eventPushOp.eventStates, entryState)
		sub.lastPushedSeq = entryState.seq
		pushes++
	}
	for _, pushOp := range pushOps {
		r.sendSessionOp(session, pushOp)
	}
	if pushes > 0 {
		logS(sessionID, "relay.debounce.push pushes=%d ops=%d", pushes, len(pushOps))
	}
	r.assertCursors(sessionID, shopState, sub)

	// If there are no buffered events at this point, it's safe to advance the acked pointer.
	if len(sub.buffer) == 0 && sub.lastAckedSeq < sub.lastPushedSeq {
		logS(sessionID, "relay.debounceSessions.advanceSeq reason=emptyBuffer from=%d to=%d", sub.lastAckedSeq, sub.lastPushedSeq)
		sub.lastAckedSeq = sub.lastPushedSeq
	}
	r.assertCursors(sessionID, shopState, sub)

	// logS(sessionID, "relay.debounce.cursors lastWrittenSeq=%d lastStatusedshopSeq=%d lastBufferedshopSeq=%d lastPushedshopSeq=%d lastAckedSeq=%d", userState.lastWrittenSeq, sessionState.lastStatusedshopSeq, sessionState.lastBufferedshopSeq, sessionState.lastPushedshopSeq, sessionState.lastAckedSeq)
}

func (r *Relay) memoryStats() {
	start := now()
	debug("relay.memoryStats.start")

	// Shared between old and sharing worlds.
	sessionCount := r.sessionIDsToSessionStates.Size()
	sessionVersionCounts := make(map[uint]uint64)
	r.sessionIDsToSessionStates.All(func(_ sessionID, sessionState *SessionState) bool {
		sessionVersionCount := sessionVersionCounts[sessionState.version]
		sessionVersionCounts[sessionState.version] = sessionVersionCount + 1
		return false
	})
	r.metric.gaugeSet("sessions_active", float64(sessionCount))
	for version, versionCount := range sessionVersionCounts {
		// TODO: vector?
		r.metric.gaugeSet(fmt.Sprintf("sessions_active_version_%d", version), float64(versionCount))
	}
	r.metric.gaugeSet("relay_cached_shops", float64(r.shopIDsToShopState.Size()))

	r.metric.gaugeSet("relay_ops_queued", float64(len(r.ops)))

	// r.metric.emit("relay_cached_items", uint64(r.listingsByListingID.loaded.Size()))
	// r.metric.emit("relay_cached_orders", uint64(r.ordersByOrderID.loaded.Size()))

	// Go runtime memory information
	var runtimeMemory runtime.MemStats
	runtime.ReadMemStats(&runtimeMemory)
	r.metric.gaugeSet("go_runtime_heapalloc", float64(runtimeMemory.HeapAlloc))
	r.metric.gaugeSet("go_runtime_inuse", float64(runtimeMemory.HeapInuse))
	r.metric.gaugeSet("go_runtime_gcpauses", float64(runtimeMemory.PauseTotalNs))

	memoryStatsTook := took(start)
	r.metric.gaugeSet("relay_memoryStats_took", float64(memoryStatsTook))
	debug("relay.memoryStats.finish took=%d", memoryStatsTook)
}

func newPool() *pgxpool.Pool {
	syncPool, err := pgxpool.Connect(context.Background(), mustGetEnvString("DATABASE_URL"))
	check(err)
	return syncPool
}

//go:generate stringer -output gen_tickType_string.go -trimprefix tt -type tickType  .

type tickType uint

const (
	ttInvalid tickType = iota
	ttWait
	ttOp
	ttOpInternal
	ttDebounceSessions
	ttPaymentWatcher
	ttMemoryStats
	ttTickStats
)

var allTickTypes = [...]tickType{
	ttWait,
	ttOp,
	ttOpInternal,
	ttDebounceSessions,
	ttPaymentWatcher,
	ttMemoryStats,
	ttTickStats,
}

func timeTick(tt tickType) (tickType, time.Time) {
	return tt, now()
}

func (r *Relay) run() {
	assert(r.writesEnabled)
	log("relay.run")
	defer sentryRecover()

	debounceSessionsTimer := NewReusableTimer(databaseDebounceInterval)
	memoryStatsTimer := NewReusableTimer(memoryStatsInterval)
	tickStatsTimer := NewReusableTimer(tickStatsInterval)

	tickTypeToTooks := make(map[tickType]time.Duration, len(allTickTypes))
	for _, tt := range allTickTypes {
		tickTypeToTooks[tt] = 0
	}

	for {
		var (
			tickType     = ttInvalid
			tickStart    = now()
			tickSelected time.Time
		)

		select {

		case op := <-r.ops:
			tickType, tickSelected = timeTick(ttOp)
			op.process(r)

		case op := <-r.opsInternal:
			tickType, tickSelected = timeTick(ttOpInternal)
			op.process(r)

		case <-debounceSessionsTimer.C:
			tickType, tickSelected = timeTick(ttDebounceSessions)
			r.debounceSessions()
			debounceSessionsTimer.Rewind()

		case <-memoryStatsTimer.C:
			tickType, tickSelected = timeTick(ttMemoryStats)
			r.memoryStats()
			memoryStatsTimer.Rewind()

		case <-tickStatsTimer.C:
			tickType, tickSelected = timeTick(ttTickStats)
			for tt, e := range tickTypeToTooks {
				if e.Milliseconds() > 0 {
					r.metric.gaugeSet(fmt.Sprintf("relay_run_tick_%s_took", tt.String()), float64(e.Milliseconds()))
				}
				tickTypeToTooks[tt] = 0
			}
			tickStatsTimer.Rewind()
		}

		assert(tickType != ttInvalid)
		assert(!tickSelected.IsZero())
		tickWait := tickSelected.Sub(tickStart)
		tickTook := time.Since(tickSelected)
		tickTypeToTooks[ttWait] += tickWait
		e, ok := tickTypeToTooks[tickType]
		assert(ok)
		e += tickTook
		tickTypeToTooks[tickType] = e
		if tickTook > tickBlockThreshold {
			log("relay.run.tick.block type=%s took=%d", tickType, tickTook.Milliseconds())
		}
	}
}
