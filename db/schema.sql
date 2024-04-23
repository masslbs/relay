-- SPDX-FileCopyrightText: 2024 Mass Labs
--
-- SPDX-License-Identifier: GPL-3.0-or-later

create type eventTypeEnum as enum ('storeManifest', 'updateManifest', 'createItem', 'updateItem', 'createTag', 'addToTag', 'removeFromTag', 'renameTag', 'deleteTag', 'createCart', 'changeCart', 'cartFinalized', 'cartAbandoned', 'changeStock', 'newKeyCard');

create table stores (
    id bytea primary key not null,
    tokenId NUMERIC(78, 0) not null
);

create table keyCards (
    id bytea not null,
    cardPublicKey bytea not null,
    userWalletAddr bytea not null,
    storeId bytea not null,
    linkedAt timestamptz not null,
    unlinkedAt timestamptz,
    lastAckedStoreSeq bigint not null,
    lastSeenAt timestamptz not null,
    lastVersion integer not null
);
create unique index keyCardsOnId on keyCards(id);
create unique index keyCardsOnPublicKey on keyCards(cardPublicKey);
create index keyCardsOnUserId on keyCards(userWalletAddr);
create index keyCardsOnStoreId on keyCards(storeId);

-- Take care to order these as they appear in network-schema/schema.proto
create type manifestFieldEnum as enum ('domain', 'paymentAddr', 'publishedTagId', 'addErc20', 'removeErc20');
create type itemFieldEnum as enum ('price', 'metadata');

create table events (
    -- Every event has these.
    eventType eventTypeEnum not null,
    eventId bytea not null,
    createdByKeyCardId bytea not null,
    createdByStoreId bytea not null,
    storeSeq bigint not null,
    createdAt timestamptz not null,
    createdByNetworkSchemaVersion bigint not null,
    serverSeq bigint not null,
    signature bytea not null,

    -- Used by one or more event types but not shared by all.
    -- Columns names must exactly match message attribute names.
    -- Columns must only shared by event types when the attribute on those
    -- events has exactly the same name and exactly the same meaning.
    -- This means the same attribute name must not be used on two different
    -- message if they don't have the same type + mean the same thing.
    storeTokenId bytea,
    domain text, -- Website URL of the store
    publishedTagId bytea, -- the system tag used to list active items
    manifestUpdateField manifestFieldEnum,
    string text,
    referencedEventId bytea,
    addr bytea,
    itemId bytea,
    price decimal(10, 2),
    metadata bytea, -- should be valid JSON
    itemUpdateField itemFieldEnum,
    name text,
    tagId bytea,
    cartId bytea,
    quantity integer,
    itemIds bytea[],
    changes integer[],
    txHash bytea,
    purchaseAddr bytea,
    erc20Addr bytea,
    subTotal decimal(15, 2),
    salesTax decimal(12, 2),
    total decimal(15, 2),
    totalInCrypto text,
     -- slight de-normalization to avoid going through keyCards table
    userWallet bytea,
    cardPublicKey bytea
);
alter table events add constraint eventsId check (octet_length(eventId) = 32);
alter table events add constraint eventsSignature check (octet_length(signature) = 65);

-- Validate schema for each particular event type.
alter table events add constraint eventsStoreManifestCheck check (eventType != 'storeManifest' OR
  (storeTokenId is not null AND length(storeTokenId) = 32 AND domain is not null AND publishedTagId is not null AND octet_length(publishedTagId) = 32));
alter table events add constraint eventsUpdateManifestCheck check (eventType != 'updateManifest' OR
  (manifestUpdateField is not null AND (string is not null OR (referencedEventId is not null AND octet_length(referencedEventId) = 32) OR (addr is not null AND octet_length(addr) = 20))));
alter table events add constraint eventsCreateItemCheck check (eventType != 'createItem' OR
  (itemId is not null AND price is not null AND metadata is not null AND octet_length(metadata) < 5*1024));
alter table events add constraint eventsUpdateItemCheck check (eventType != 'updateItem' OR
  (itemId is not null AND itemUpdateField is not null AND (price is not null OR (metadata is not null AND octet_length(metadata) < 5*1024))));
alter table events add constraint eventsCreateTagCheck check (eventType != 'createTag' OR
  (tagId is not null AND name is not null));
alter table events add constraint eventsAddToTagCheck check (eventType != 'addToTag' OR
  (tagId is not null AND itemId is not null));
alter table events add constraint eventsRemoveFromTagCheck check (eventType != 'removeFromTag' OR
  (tagId is not null AND itemId is not null));
alter table events add constraint eventsRenameTagCheck check (eventType != 'renameTag' OR
  (tagId is not null AND name is not null));
alter table events add constraint eventsDeleteTagCheck check (eventType != 'deleteTag' OR
  (tagId is not null));
alter table events add constraint eventsCreateCartCheck check (eventType != 'createCart' OR
  (cartId is not null));
alter table events add constraint eventsChangeCartCheck check (eventType != 'changeCart' OR
  (cartId is not null AND itemId is not null AND quantity is not null));
alter table events add constraint eventsCartFinalizedCheck check (eventType != 'cartFinalized' OR
  (cartId is not null AND purchaseAddr is not null AND octet_length(purchaseAddr) = 20 AND subTotal is not null AND salesTax is not null AND total is not null AND totalInCrypto is not null AND (erc20Addr is null OR octet_length(erc20Addr) = 20)));
alter table events add constraint eventsCartAbandonedCheck check (eventType != 'cartAbandoned' OR
  (cartId is not null));
alter table events add constraint eventsChangeStockCheck check (eventType != 'changeStock' OR
  (itemIds is not null AND changes is not null));
alter table events add constraint eventsNewKeyCardCheck check (eventType != 'newKeyCard' OR
  (userWallet is not null AND octet_length(userWallet) = 20 AND cardPublicKey is not null AND octet_length(cardPublicKey) = 64));


-- Indicies that apply to all events.
create unique index eventsOnEventId on events(eventId);
create unique index eventsOnServerSeq on events(serverSeq);
create unique index eventsOnStoreSeq on events(createdByStoreId, storeSeq);

-- Indicies that apply to a subset of events, used to load events of a specific type by a non-eventId field.
-- Should correspond with Loader definitions in newDatabase.
-- create index eventsOnEventTypeAndScopeId on events(eventType, scopeId) where eventType in ('scopeSetInclusion', 'pack', 'blob');
-- create index eventsOnEventTypeAndScopeSetId on events(eventType, scopeSetId) where eventType in ('scopeSetInclusion', 'scopeSetPermission');
-- create index eventsOnEventTypeAndUserId on events(eventType, userId) where eventType in ('userSetInclusion');
-- create index eventsOnEventTypeAndUserSetId on events(eventType, userSetId) where eventType in ('userSetInclusion', 'scopeSetPermission');

CREATE TABLE payments (
    waiterId         bytea PRIMARY KEY NOT NULL,
    cartId           bytea NOT NULL,
    createdByStoreId bytea NOT NULL,
    storeSeqNo       bigint not null, -- the seqNo of store when the cart was finalized
    cartFinalizedAt  TIMESTAMP NOT NULL,
    purchaseAddr     bytea NOT NULL,
    lastBlockNo      NUMERIC(80,0) NOT NULL,
    coinsPayed       NUMERIC(80,0) NOT NULL,
    coinsTotal       NUMERIC(80,0) NOT NULL,
    -- (optional) set if the cart is payed with an erc20 token
    erc20TokenAddr   bytea,
    -- set once payed
    cartPayedAt     TIMESTAMP,
    cartPayedTx     bytea
);

alter table payments add constraint erc20TokenAddrCheck check (erc20TokenAddr is null or octet_length(erc20TokenAddr) = 20);

CREATE UNIQUE INDEX paymentsCartId ON payments (cartId);
CREATE INDEX paymentsCartFinalizedAt ON payments (cartFinalizedAt);
CREATE INDEX paymentsCartPayedAt ON payments (cartPayedAt);
