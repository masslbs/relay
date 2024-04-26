-- SPDX-FileCopyrightText: 2024 Mass Labs
--
-- SPDX-License-Identifier: GPL-3.0-or-later

create type eventTypeEnum as enum ('storeManifest', 'updateStoreManifest', 'createItem', 'updateItem', 'createTag', 'updateTag', 'createOrder', 'updateOrder', 'changeStock', 'newKeyCard');

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
    lastAckedKCSeq bigint not null,
    lastSeenAt timestamptz not null,
    lastVersion integer not null,
    isGuest boolean not null
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
    encoded bytea not null,
    referenceId bytea
);
alter table events add constraint eventsId check (octet_length(eventId) = 32);
-- TODO: cap size of encoded column
alter table events add constraint eventsCheckReferenceIdForCreateItem check (
    eventType != 'createItem' OR (referenceId is not null AND octet_length(referenceId) = 32));
alter table events add constraint eventsCheckReferenceIdForUpdateItem check (
    eventType != 'updateItem' OR (referenceId is not null AND octet_length(referenceId) = 32));
alter table events add constraint eventsCheckReferenceIdForCreateTag check (
    eventType != 'createTag' OR (referenceId is not null AND octet_length(referenceId) = 32));
alter table events add constraint eventsCheckReferenceIdForUpdateTag check (
    eventType != 'updateTag' OR (referenceId is not null AND octet_length(referenceId) = 32));
alter table events add constraint eventsCheckReferenceIdForCreateCart check (
    eventType != 'createOrder' OR (referenceId is not null AND octet_length(referenceId) = 32));
alter table events add constraint eventsCheckReferenceIdForChangeCart check (
    eventType != 'updateOrder' OR (referenceId is not null AND octet_length(referenceId) = 32));

-- Indicies that apply to all events.
create unique index eventsOnEventId on events(eventId);
create unique index eventsOnServerSeq on events(serverSeq);
create unique index eventsOnStoreSeq on events(createdByStoreId, storeSeq);

create table eventPropagations (
    eventId bytea not null
);

create table keyCardEvents (
    keyCardId bytea not null,
    keyCardSeq bigint not null,
    eventStoreSeq bigint not null
);
create unique index keyCardStoreEvtUnique on keyCardEvents(keyCardId, eventStoreSeq);
create unique index keyCardEventsSeqsUnique on keyCardEvents(keyCardId, keyCardSeq);

CREATE TABLE payments (
    waiterId         bytea PRIMARY KEY NOT NULL,
    orderId          bytea NOT NULL,
    paymentId        bytea NOT NULL, -- uint256
    createdByStoreId bytea NOT NULL,
    storeSeqNo       bigint not null, -- the seqNo of store when the order was finalized
    orderFinalizedAt  TIMESTAMP NOT NULL,
    purchaseAddr     bytea NOT NULL,
    lastBlockNo      NUMERIC(80,0) NOT NULL,
    coinsPayed       NUMERIC(80,0) NOT NULL,
    coinsTotal       NUMERIC(80,0) NOT NULL,
    -- (optional) set if the order is payed with an erc20 token
    erc20TokenAddr   bytea,
    -- set once payed
    orderPayedAt     TIMESTAMP,
    orderPayedTx     bytea
);

alter table payments add constraint erc20TokenAddrCheck check (erc20TokenAddr is null or octet_length(erc20TokenAddr) = 20);

CREATE UNIQUE INDEX paymentsOrderId ON payments (orderId);
CREATE INDEX paymentsOrderFinalizedAt ON payments (orderFinalizedAt);
CREATE INDEX paymentsOrderPayedAt ON payments (orderPayedAt);
