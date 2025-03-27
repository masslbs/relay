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

	"github.com/go-playground/validator/v10"
	clone "github.com/huandu/go-clone/generic"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	cbor "github.com/masslbs/network-schema/go/cbor"
	"github.com/masslbs/network-schema/go/objects"
	"github.com/masslbs/network-schema/go/patch"
)

// PushStates represents the state of an event in the database.
type PushStates struct {
	acked bool

	shopSeq   uint64
	leafIndex uint32

	patchData, patchInclProof []byte
	psHeader, psSignature     []byte
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
	buffer              []*PushStates
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

// ShopState helps with writing events to the database
type ShopState struct {
	lastUsedSeq    uint64
	lastWrittenSeq uint64

	relayKeyCardID             keyCardID
	lastWrittenRelayEventNonce uint64
	shopTokenID                big.Int

	data *objects.Shop
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

	validator *validator.Validate

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

	r.validator = objects.DefaultValidator()
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
func (r *Relay) bulkInsert(table string, columns []string, rows [][]interface{}) [][]interface{} {
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
	qb.WriteString(")")
	q := qb.String()
	insertedRows := make([][]interface{}, 0)
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
		} else {
			panic(fmt.Errorf("unexpected rowsAffected=%d", rowsAffected))
		}
	}
	check(br.Close())
	if r.syncTx == nil {
		check(tx.Commit(ctx))
	}
	debug("relay.bulkInsert table=%s columns=%d rows=%d insertedRows=%d  elapsed=%d", table, len(columns), len(rows), len(insertedRows), took(start))
	return insertedRows
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
// the bool signals if the shop was created or not
func (r *Relay) getOrCreateInternalShopID(shopTokenID big.Int) (ObjectIDArray, uint64, bool) {
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
		return shopID, dbID, false
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
	newShop := objects.NewShop(4)
	r.shopIDsToShopState.Set(shopID, &ShopState{
		relayKeyCardID: relayKCID,
		data:           &newShop,
	})

	return shopID, dbID, true
}

func (r *Relay) hydrateShops(shopIDs *SetInts[ObjectIDArray]) {
	total := now()
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
			data := objects.NewShop(4)
			shopState.data = &data
			r.shopIDsToShopState.Set(shopID, shopState)
			return false
		})
		novelIDArrays := novelShopIDs.Slice()
		arraysToSlices := make([][]byte, len(novelIDArrays))
		for i, arr := range novelIDArrays {
			arraysToSlices[i] = arr[:]
		}
		for _, novelShopIDsSubslice := range subslice(arraysToSlices, 256) {
			start := now()
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
			log("relay.hydrateShops.shopSeq took=%d", took(start))

			start = now()
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
			log("relay.hydrateShops.relayKeyCards took=%d", took(start))

			// TODO: load all patches for the shop and apply them
			start = now()
			const queryAllPatchesForShop = `select ps.createdByShopId, p.encoded
from patchSets ps
join patches p on ps.serverSeq = p.patchsetServerSeq
where ps.createdByShopId = any($1)
order by ps.serverSeq, p.patchIndex`
			rows, err = r.connPool.Query(ctx, queryAllPatchesForShop, novelShopIDsSubslice)
			check(err)
			var rowCount int
			for rows.Next() {
				var shopID ObjectIDArray
				var shopIDArray []byte
				var patchData []byte
				err = rows.Scan(&shopIDArray, &patchData)
				check(err)
				n := copy(shopID[:], shopIDArray)
				assert(n == 8)
				shopState := r.shopIDsToShopState.MustGet(shopID)
				// applying patches directly to the shop state since all writes were verified in the past
				patcher := patch.NewPatcher(r.validator, shopState.data)

				var p patch.Patch
				err = cbor.Unmarshal(patchData, &p)
				check(err)
				err = patcher.ApplyPatch(p)
				check(err)
				rowCount++
			}
			check(rows.Err())
			rows.Close()
			log("relay.hydrateShops.events rowCount=%d took=%d", rowCount, took(start))
		}
	}
	elapsed := took(total)
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

// PatchSetInsert is a struct that represents an event to be inserted into the database
type PatchSetInsert struct {
	CachedMetadata
	psetHeaderData []byte
	pset           *patch.SignedPatchSet
	proofs         [][]byte
}

func (r *Relay) queuePatchSet(cm CachedMetadata, pset *patch.SignedPatchSet, headerData []byte, proofs [][]byte) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	shopSeqPair := r.shopIDsToShopState.MustGet(cm.createdByShopID)
	cm.shopSeq = shopSeqPair.lastUsedSeq + 1
	shopSeqPair.lastUsedSeq = cm.shopSeq

	assert(len(proofs) == len(pset.Patches))
	insert := &PatchSetInsert{
		CachedMetadata: cm,
		psetHeaderData: headerData,
		pset:           pset,
		proofs:         proofs,
	}
	r.queuedPatchSetInserts = append(r.queuedPatchSetInserts, insert)
}

func (r *Relay) createRelayPatchSet(shopID ObjectIDArray, patches ...patch.Patch) {
	shopState := r.shopIDsToShopState.MustGet(shopID)
	header := &patch.SetHeader{
		KeyCardNonce: shopState.nextRelayEventNonce(),
		ShopID:       shopState.shopTokenID,
		Timestamp:    time.Now(),
	}

	var err error
	rootHash, tree, err := patch.RootHash(patches)
	check(err)
	header.RootHash = rootHash

	var pset patch.SignedPatchSet
	pset.Header = *header
	pset.Patches = patches
	headerData, err := cbor.Marshal(header)
	check(err)
	sig, err := r.ethereum.sign(headerData)
	check(err)
	pset.Signature = *sig

	proofs := make([][]byte, len(patches))
	for i := uint64(0); i < uint64(len(patches)); i++ {
		p, err := tree.MakeProof(i)
		check(err)
		proofs[i], err = cbor.Marshal(p)
		check(err)
	}

	meta := newMetadata(shopState.relayKeyCardID, shopID, currentRelayVersion)
	meta.writtenByRelay = true
	r.queuePatchSet(meta, &pset, headerData, proofs)
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
	r.flushPatchSets()
	for _, insert := range r.queuedPatchSetInserts {
		if insert.writtenByRelay {
			shopState := r.shopIDsToShopState.MustGet(insert.createdByShopID)
			proposal := clone.Clone(shopState.data)
			for i, p := range insert.pset.Patches {
				patcher := patch.NewPatcher(r.validator, proposal)
				if err := patcher.ApplyPatch(p); err != nil {
					log("relay.commitSyncTransaction.applyPatchFailed shopID=%x serverSeq=%d patch=%d err=%s",
						insert.createdByShopID,
						insert.serverSeq,
						i,
						err,
					)
					check(err)
					return
				}
			}
			shopState.data = proposal
		}
	}
	ctx := context.Background()
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

var dbPatchSetInsertColumns = []string{"serverSeq", "keycardNonce", "createdByKeyCardId", "createdByNetworkSchemaVersion", "createdByShopId", "shopSeq", "createdAt", "receivedAt", "header", "signature"}

func formPatchSetHeaderInsert(ins *PatchSetInsert) []interface{} {
	return []interface{}{
		ins.serverSeq,                // serverSeq
		ins.pset.Header.KeyCardNonce, // keycardNonce
		ins.createdByKeyCardID,       // createdByKeyCardID
		ins.createdByNetworkVersion,  // createdByNetworkSchemaVersion
		ins.createdByShopID[:],       // createdByShopID
		ins.shopSeq,                  // shopSeq
		ins.pset.Header.Timestamp,    // createdAt
		now(),                        // receivedAt
		ins.psetHeaderData,           // header
		ins.pset.Signature[:],        // signature
	}
}

var dbPatchInsertColumns = []string{"patchsetServerSeq", "patchIndex", "op", "objectType", "objectId", "accountAddr", "tagName", "encoded", "mmrProof"}

func formPatchInsert(p patch.Patch, patchIndex int, serverSeq uint64, proof []byte) []interface{} {
	// pgx does not know how to handle cbor.* types.
	// therefore, we need to "type down" the cbor.* types to basic types
	// tagName is a *string and is handled correctly automatically
	var addr *[]byte
	var objID *[]byte
	if id := p.Path.AccountAddr; id != nil {
		sliced := id.Address[:]
		addr = &sliced
	}
	if id := p.Path.ObjectID; id != nil {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, *id)
		objID = &buf
	}
	// TODO: re-use this data from the initial decode stage during write validation
	fullPatch, err := cbor.Marshal(p)
	check(err)
	return []interface{}{
		serverSeq,      // patch_set_server_seq
		patchIndex,     // patch_index
		p.Op,           // op
		p.Path.Type,    // object_type
		objID,          // object_id
		addr,           // account_addr
		p.Path.TagName, // tag_name
		fullPatch,      // encoded
		proof,          // mmr_proof
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

	insertedPatchSets := r.bulkInsert("patchSets", dbPatchSetInsertColumns, patchSetTuples)
	for _, row := range insertedPatchSets {
		rowServerSeq := row[0].(uint64)
		assert(r.lastWrittenServerSeq < rowServerSeq)
		assert(rowServerSeq <= r.lastUsedServerSeq)
		r.lastWrittenServerSeq = rowServerSeq
		rowShopID := row[4].([]byte)
		assert(len(rowShopID) == 8)
		rowShopSeq := row[5].(uint64)
		shopState := r.shopIDsToShopState.MustGet(ObjectIDArray(rowShopID))
		assert(shopState.lastWrittenSeq < rowShopSeq)
		assert(rowShopSeq <= shopState.lastUsedSeq)
		shopState.lastWrittenSeq = rowShopSeq
	}
	assert(r.lastWrittenServerSeq <= r.lastUsedServerSeq)
	log("relay.flushPatchSets.patchSets insertedSets=%d", len(insertedPatchSets))

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

	// Insert the patches that belong to each patchSet
	var patchTuples [][]any
	for _, ins := range r.queuedPatchSetInserts {
		for i, patch := range ins.pset.Patches {
			patchTuples = append(patchTuples, formPatchInsert(patch, i, ins.serverSeq, ins.proofs[i]))
		}
	}
	insertedPatchRows := r.bulkInsert("patches", dbPatchInsertColumns, patchTuples)
	log("relay.flushPatchSets.patches insertedPatches=%d", len(insertedPatchRows))

	log("relay.flushPatchSets.finish took=%d", took(start))
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
		// TODO: patchSets/shopSeq vs pushed patches in a subscription are not the same anymore.
		// we need to make sure that the shopSeq is >= the lastAckedSeq
		assert(entryState.shopSeq >= sub.lastAckedSeq)
		if i == 0 {
			advancedFrom = sub.lastAckedSeq
		}
		sub.lastAckedSeq = entryState.shopSeq
		advancedTo = entryState.shopSeq
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
		// Index: patchSets(createdByShopId, shopSeq)
		query := `select count(*)
			from patchSets ps
			right join patches p on p.patchsetServerSeq = ps.serverSeq
			where ps.createdByShopId = $1 and ps.shopSeq > $2
			  and (` + sub.whereFragment + `)`
		err := r.connPool.QueryRow(ctx, query, sub.shopID[:], sub.lastPushedSeq).
			Scan(&op.unpushedPatches)
		if err != pgx.ErrNoRows {
			check(err)
		}
		r.sendSessionOp(session, op)
		sub.initialStatus = true
		sub.lastStatusedSeq = shopState.lastWrittenSeq
		if op.unpushedPatches == 0 {
			sub.lastBufferedSeq = sub.lastStatusedSeq
			sub.lastPushedSeq = sub.lastStatusedSeq
		}
		logS(sessionID, "relay.debounceSessions.syncStatus initialStatus=%t unpushedPatches=%d elapsed=%d", sub.initialStatus, op.unpushedPatches, took(syncStatusStart))
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
		// Index: patchSets(createdByShopId, shopSeq) on patches(patchsetServerSeq)
		query := `select ps.shopSeq, ps.header, ps.signature, p.encoded, p.mmrProof
				from patchSets ps
				right join patches p on p.patchsetServerSeq = ps.serverSeq
				where ps.createdByShopId = $1
				    and ps.shopSeq > $2
					and (` + sub.whereFragment + `) order by ps.shopSeq asc limit $3`
		rows, err := r.connPool.Query(ctx, query, sub.shopID[:], sub.lastPushedSeq, readsAllowed)
		check(err)
		defer rows.Close()
		for rows.Next() {
			var pushStates = &PushStates{}
			err := rows.Scan(&pushStates.shopSeq, &pushStates.psHeader, &pushStates.psSignature,
				&pushStates.patchData, &pushStates.patchInclProof)
			check(err)
			reads++
			// log("relay.debounceSessions.debug event=%x", PushStates.eventID)

			pushStates.acked = false
			sub.buffer = append(sub.buffer, pushStates)
			// logS(sessionID, "relay.debounceSessions.debug bufferLen=%d lastBufferedSeq=%d pushStates.shopSeq=%d", len(sub.buffer), sub.lastBufferedSeq, pushStates.shopSeq)
			// TODO: pushes and the shopSeq are not the same anymore.
			// we now have multiple patches in one patchset, which is the sequenced entity.
			// so we need to check if the pushStates.shopSeq is >= the lastBufferedSeq
			// and if so, we can advance the lastBufferedSeq
			assert(pushStates.shopSeq >= sub.lastBufferedSeq)
			sub.lastBufferedSeq = pushStates.shopSeq
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
		if eventPushOp != nil && len(eventPushOp.pushStates) == limitMaxOutBatchSize {
			eventPushOp = nil
		}
		if eventPushOp == nil {
			eventPushOp = &SubscriptionPushOp{
				sessionID:      sessionID,
				subscriptionID: subID,
				pushStates:     make([]*PushStates, 0),
			}
			pushOps = append(pushOps, eventPushOp)
		}
		eventPushOp.pushStates = append(eventPushOp.pushStates, entryState)
		sub.lastPushedSeq = entryState.shopSeq
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
