-- SPDX-FileCopyrightText: 2024 Mass Labs
--
-- SPDX-License-Identifier: GPL-3.0-or-later

create type eventTypeEnum as enum ('manifest', 'updateManifest', 'listing', 'updateListing', 'tag', 'updateTag', 'createOrder', 'updateOrder', 'changeInventory', 'account');

create table shops (
    id serial,
    tokenId NUMERIC(78, 0) not null,
    createdAt timestamptz not null
);

CREATE SEQUENCE keyCard_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

create table keyCards (
    id integer DEFAULT nextval('keyCard_id_seq') PRIMARY KEY,
    cardPublicKey bytea not null,
    userWalletAddr bytea not null,
    shopId integer not null,
    linkedAt timestamptz not null,
    unlinkedAt timestamptz,
    lastAckedSeq bigint not null,
    lastSeenAt timestamptz not null,
    lastVersion integer not null,
    isGuest boolean not null
);
create unique index keyCardsOnPublicKey on keyCards(cardPublicKey);
create index keyCardsOnUserId on keyCards(userWalletAddr);
create index keyCardsOnShopId on keyCards(shopId);


create table relayKeyCards (
    id integer DEFAULT nextval('keyCard_id_seq') PRIMARY KEY,
    shopId integer not null,
    cardPublicKey bytea not null,
    lastUsedAt timestamptz not null,
    lastWrittenEventNonce bigint not null
);

create table events (
    id serial,
    -- Every event has these.
    eventType eventTypeEnum not null,
    eventNonce bigint not null,
    createdByKeyCardId bigint not null,
    createdByShopId bigint not null,
    shopSeq bigint not null,
    createdAt timestamptz not null,
    createdByNetworkSchemaVersion bigint not null,
    serverSeq bigint not null,
    encoded bytea not null,
    signature bytea not null,
    objectId bigint
);
alter table events add constraint eventsSignatures check (octet_length(signature) = 65);
-- TODO: cap size of encoded column
alter table events add constraint eventsCheckReferenceIdForCreateItem check (
    eventType != 'listing' OR (objectId is not null));
alter table events add constraint eventsCheckReferenceIdForUpdateItem check (
    eventType != 'updateListing' OR (objectId is not null));
alter table events add constraint eventsCheckReferenceIdForCreateTag check (
    eventType != 'tag' OR (objectId is not null));
alter table events add constraint eventsCheckReferenceIdForUpdateTag check (
    eventType != 'updateTag' OR (objectId is not null));
alter table events add constraint eventsCheckReferenceIdForCreateCart check (
    eventType != 'createOrder' OR (objectId is not null));
alter table events add constraint eventsCheckReferenceIdForChangeCart check (
    eventType != 'updateOrder' OR (objectId is not null));

-- Indicies that apply to all events.
create unique index eventsOnServerSeq on events(serverSeq);
create unique index eventsOnEventNonce on events(createdByKeyCardId, eventNonce);
create unique index eventsOnShopSeq on events(createdByShopId, shopSeq);

CREATE TABLE payments (
    id               serial,
    orderId          bigint NOT NULL,
    shopId           bigint NOT NULL,
    shopSeqNo        bigint not null, -- the seqNo of shop when the order was finalized
    itemsLockedAt TIMESTAMP NOT NULL,

    -- set once payment method was chosen
    paymentChosenAt TIMESTAMP,
    paymentId        bytea, -- uint256
    purchaseAddr     bytea,
    chainId          integer,
    lastBlockNo      NUMERIC(80,0),
    coinsPayed       NUMERIC(80,0),
    coinsTotal       NUMERIC(80,0),
    -- (optional) set if the order is payed with an erc20 token
    erc20TokenAddr   bytea,

    -- set once payed
    payedAt     TIMESTAMP,
    payedTx     bytea,
    payedBlock  bytea

);
alter table payments add constraint paymentIdLength check (octet_length(paymentId) = 32);
alter table payments add constraint erc20TokenAddrCheck check (erc20TokenAddr is null OR octet_length(erc20TokenAddr) = 20);
alter table payments add constraint paymentChosen check (paymentChosenAt is null OR (
    paymentId is not null OR
    purchaseAddr is not null OR
    chainId is not null OR
    lastBlockNo is not null OR
    coinsPayed  is not null OR
    coinsTotal  is not null
));
alter table payments add constraint paidHash check (payedAt is null or (
    payedTx is not null OR payedBlock is not null
));

CREATE UNIQUE INDEX paymentsOrderId ON payments (shopId, orderId);
CREATE INDEX paymentsOrderFinalizedAt ON payments (paymentChosenAt);
CREATE INDEX paymentsPayedAt ON payments (payedAt);
