// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	cbor "github.com/masslbs/network-schema/go/cbor"
)

// EventState represents the state of an event in the database.
type EventState struct {
	seq   uint64
	acked bool

	// encodedEvent SignedEvent
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

func newCachedShopCurrency(sc *cbor.ChainAddress) cachedShopCurrency {
	assert(sc.ChainID != 0)
	return cachedShopCurrency{
		Addr:    common.Address(sc.Address),
		ChainID: sc.ChainID,
	}
}

func (a cachedShopCurrency) Equal(b cachedShopCurrency) bool {
	return a.ChainID == b.ChainID && a.Addr.Cmp(b.Addr) == 0
}

type cachedCurrenciesMap map[cachedShopCurrency]struct{}

// ShopState helps with writing events to the database
type ShopState struct {
	lastUsedSeq    uint64
	lastWrittenSeq uint64

	relayKeyCardID             keyCardID
	lastWrittenRelayEventNonce uint64
	shopTokenID                big.Int
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
	syncTx                pgx.Tx
	queuedPatchSetInserts []*PatchSetInsert
	shopIDsToShopState    *MapInts[ObjectIDArray, *ShopState] // Changed from shopIdsToShopState
	lastUsedServerSeq     uint64
	lastWrittenServerSeq  uint64

	// caching layer
	// shopManifestsByShopID *ReductionLoader[*CachedShopManifest]
	// listingsByListingID   *ReductionLoader[*CachedListing]
	// stockByShopID         *ReductionLoader[*CachedStock]
	// tagsByTagID           *ReductionLoader[*CachedTag]
	// ordersByOrderID       *ReductionLoader[*CachedOrder]
	// allLoaders            []Loader

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

	/*
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
	*/
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
			const queryLatestShopSeq = `select createdByShopId, max(shopSeq) from patchSets where createdByShopId = any($1) group by createdByShopId`
			rows, err := r.connPool.Query(ctx, queryLatestShopSeq, novelShopIDsSubslice)
			check(err)
			for rows.Next() {
				var eventsShopID SQLUint64Bytes
				var lastWrittenSeq *uint64
				err = rows.Scan(&eventsShopID, &lastWrittenSeq)
				check(err)
				shopState := r.shopIDsToShopState.MustGet(eventsShopID.Data)
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
	err := r.connPool.QueryRow(context.Background(), `select serverSeq from patchSets order by serverSeq desc limit 1`).Scan(&r.lastWrittenServerSeq)
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

// func (r *Relay) readEvents(whereFragment string, shopID, objectID ObjectIDArray) []PatchSetInsert {
// 	// Index: events(field in whereFragment)
// 	// The indicies eventsOnEventTypeAnd* should correspond to the various Loaders defined in newDatabase.
// 	query := fmt.Sprintf(`select serverSeq, shopSeq, eventType, createdByKeyCardId, createdAt, createdByNetworkSchemaVersion, encoded

// from events where createdByShopID = $1 and %s order by serverSeq asc`, whereFragment)

// 	var rows pgx.Rows
// 	var err error
// 	if r.syncTx != nil {
// 		rows, err = r.syncTx.Query(context.Background(), query, shopID[:], objectID[:])
// 	} else {
// 		rows, err = r.connPool.Query(context.Background(), query, shopID[:], objectID[:])
// 	}
// 	check(err)
// 	defer rows.Close()
// 	events := make([]PatchSetInsert, 0)
// 	for rows.Next() {
// 		var (
// 			m         CachedMetadata
// 			eventType eventType
// 			createdAt time.Time
// 			encoded   []byte
// 		)
// 		err := rows.Scan(&m.serverSeq, &m.shopSeq, &eventType, &m.createdByKeyCardID, &createdAt, &m.createdByNetworkVersion, &encoded)
// 		check(err)
// 		m.createdByShopID = ObjectIDArray(shopID)
// 		m.objectID = &objectID
// 		var e ShopEvent
// 		err = proto.Unmarshal(encoded, &e)
// 		check(err)
// 		events = append(events, PatchSetInsert{
// 			CachedMetadata: m,
// 			evt:            &e,
// 			evtType:        eventType,
// 		})
// 	}
// 	check(rows.Err())
// 	return events
// }

// PatchSetInsert is a struct that represents an event to be inserted into the database
type PatchSetInsert struct {
	CachedMetadata
	evtType eventType
	pset    *cbor.SignedPatchSet
}

func newPatchSetInsert(pset *cbor.SignedPatchSet, meta CachedMetadata) *PatchSetInsert {
	return &PatchSetInsert{
		CachedMetadata: meta,
		pset:           pset,
	}
}

func (r *Relay) queuePatchSet(pset *cbor.SignedPatchSet, cm CachedMetadata) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	shopSeqPair := r.shopIDsToShopState.MustGet(cm.createdByShopID)
	cm.shopSeq = shopSeqPair.lastUsedSeq + 1
	shopSeqPair.lastUsedSeq = cm.shopSeq

	insert := newPatchSetInsert(pset, cm)
	r.queuedPatchSetInserts = append(r.queuedPatchSetInserts, insert)
	// r.applyEvent(insert)
}

func (r *Relay) createRelayPatch(shopID ObjectIDArray, patch cbor.Patch) {
	shopState := r.shopIDsToShopState.MustGet(shopID)
	header := &cbor.PatchSetHeader{
		KeyCardNonce: shopState.nextRelayEventNonce(),
		ShopID:       shopState.shopTokenID,
		Timestamp:    time.Now(),
	}

	var patches []cbor.Patch
	patches = append(patches, patch)
	var err error
	header.RootHash, _, err = cbor.RootHash(patches)
	check(err)

	var pset cbor.SignedPatchSet
	pset.Header = *header
	pset.Patches = patches

	sig, err := r.ethereum.signPatchsetHeader(pset.Header)
	check(err)
	pset.Signature = *sig

	meta := newMetadata(shopState.relayKeyCardID, shopID, currentRelayVersion)
	meta.writtenByRelay = true
	r.queuePatchSet(&pset, meta)
}

func (r *Relay) beginSyncTransaction() {
	assert(r.queuedPatchSetInserts == nil)
	assert(r.syncTx == nil)
	r.queuedPatchSetInserts = make([]*PatchSetInsert, 0)
	ctx := context.Background()
	tx, err := r.connPool.Begin(ctx)
	check(err)
	r.syncTx = tx
}

func (r *Relay) commitSyncTransaction() {
	assert(r.queuedPatchSetInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	r.flushPatchSets()
	check(r.syncTx.Commit(ctx))
	r.queuedPatchSetInserts = nil
	r.syncTx = nil
}

func (r *Relay) rollbackSyncTransaction() {
	assert(r.queuedPatchSetInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	check(r.syncTx.Rollback(ctx))
	r.queuedPatchSetInserts = nil
	r.syncTx = nil
}

var dbPatchSetHeaderInsertColumns = []string{"serverSeq", "keycardNonce", "createdByKeyCardId", "createdByShopId", "shopSeq", "createdAt", "receivedAt", "rootHash", "signature"}

func formPatchSetHeaderInsert(ins *PatchSetInsert) []interface{} {
	return []interface{}{
		ins.serverSeq,                // server_seq
		ins.pset.Header.KeyCardNonce, // keycard_nonce
		ins.createdByKeyCardID,       // created_by_keycard_id
		ins.createdByNetworkVersion,  // created_by_network_schema_version
		ins.createdByShopID,          // created_by_shop_id
		ins.shopSeq,                  // shop_seq
		ins.pset.Header.Timestamp,    // created_at
		now(),                        // received_at
		ins.pset.Header.RootHash,     // root_hash
		ins.pset.Signature,           // signature
	}
}

func formPatchSetPatchesInserts(ins *PatchSetInsert) [][]interface{} {
	patches := make([][]interface{}, len(ins.pset.Patches))
	for i, patch := range ins.pset.Patches {
		patches[i] = formPatchInsert(patch, ins.serverSeq)
	}
	return patches
}

func formPatchInsert(patch cbor.Patch, serverSeq uint64) []interface{} {
	return []interface{}{
		serverSeq,             // patch_set_server_seq
		patch.Op,              // op
		patch.Path.Type,       // object_type
		patch.Path.ObjectID,   // object_id
		patch.Path.AccountID,  // account_id
		patch.Path.TagName,    // tag_name
		patch.Value,           // encoded
		[]byte("dummy_proof"), // mmr_proof
	}
}

func (r *Relay) flushPatchSets() {
	if len(r.queuedPatchSetInserts) == 0 {
		return
	}
	assert(r.writesEnabled)
	log("relay.flushPatchSets.start entries=%d", len(r.queuedPatchSetInserts))
	start := now()

	patchSetTuples := make([][]any, len(r.queuedPatchSetInserts))
	relayEvents := make(map[keyCardID]uint64)
	for i, ins := range r.queuedPatchSetInserts {
		patchSetTuples[i] = formPatchSetHeaderInsert(ins)
		if ins.writtenByRelay {
			last := relayEvents[ins.createdByKeyCardID]
			if last < ins.pset.Header.KeyCardNonce {
				relayEvents[ins.createdByKeyCardID] = ins.pset.Header.KeyCardNonce
			}
		}
	}
	assert(r.lastWrittenServerSeq < r.lastUsedServerSeq)

	insertedEventRows, conflictedEventRows := r.bulkInsert("events", dbPatchSetHeaderInsertColumns, patchSetTuples)
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
	r.queuedPatchSetInserts = nil
	log("relay.flushPatchSets.events insertedEntries=%d conflictedEntries=%d", len(insertedEventRows), len(conflictedEventRows))

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

	log("relay.flushPatchSets.finish took=%d", took(start))
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
	syncPool, err := pgxpool.New(context.Background(), mustGetEnvString("DATABASE_URL"))
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
			// TODO: re-enable sessions debounce
			// 	r.debounceSessions()
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
