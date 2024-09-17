-- SPDX-FileCopyrightText: 2024 Mass Labs
--
-- SPDX-License-Identifier: GPL-3.0-or-later

create type eventTypeEnum as enum ('manifest', 'updateManifest', 'listing', 'updateListing', 'tag', 'updateTag', 'createOrder', 'updateOrder', 'changeInventory', 'account');

create table shops (
    id serial,
    tokenId NUMERIC(78, 0) NOT NULL,
    createdAt timestamptz NOT NULL
);

CREATE SEQUENCE keyCard_id_seq START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

create table keyCards (
    id integer DEFAULT nextval('keyCard_id_seq') PRIMARY KEY,
    cardPublicKey bytea NOT NULL,
    userWalletAddr bytea NOT NULL,
    shopId integer NOT NULL,
    linkedAt timestamptz NOT NULL,
    unlinkedAt timestamptz,
    lastAckedSeq bigint NOT NULL,
    lastSeenAt timestamptz NOT NULL,
    lastVersion integer NOT NULL,
    isGuest boolean NOT NULL
);
create unique index keyCardsOnPublicKey on keyCards(cardPublicKey);
create index keyCardsOnUserId on keyCards(userWalletAddr);
create index keyCardsOnShopId on keyCards(shopId);


create table relayKeyCards (
    id integer DEFAULT nextval('keyCard_id_seq') PRIMARY KEY,
    shopId integer NOT NULL,
    cardPublicKey bytea NOT NULL,
    lastUsedAt timestamptz NOT NULL,
    lastWrittenEventNonce bigint NOT NULL
);

create table events (
    id serial,
    -- Every event has these.
    eventType eventTypeEnum NOT NULL,
    eventNonce bigint NOT NULL,
    createdByKeyCardId bigint NOT NULL,
    createdByShopId bigint NOT NULL,
    shopSeq bigint NOT NULL,
    createdAt timestamptz NOT NULL,
    createdByNetworkSchemaVersion bigint NOT NULL,
    serverSeq bigint NOT NULL,
    encoded bytea NOT NULL,
    signature bytea NOT NULL,
    objectId bigint
);
alter table events add constraint eventsSignatures check (octet_length(signature) = 65);
-- TODO: cap size of encoded column
alter table events add constraint eventsCheckReferenceIdForCreateItem check (
    eventType != 'listing' OR (objectId is NOT NULL));
alter table events add constraint eventsCheckReferenceIdForUpdateItem check (
    eventType != 'updateListing' OR (objectId is NOT NULL));
alter table events add constraint eventsCheckReferenceIdForCreateTag check (
    eventType != 'tag' OR (objectId is NOT NULL));
alter table events add constraint eventsCheckReferenceIdForUpdateTag check (
    eventType != 'updateTag' OR (objectId is NOT NULL));
alter table events add constraint eventsCheckReferenceIdForCreateCart check (
    eventType != 'createOrder' OR (objectId is NOT NULL));
alter table events add constraint eventsCheckReferenceIdForChangeCart check (
    eventType != 'updateOrder' OR (objectId is NOT NULL));

-- Indicies that apply to all events.
create unique index eventsOnServerSeq on events(serverSeq);
create unique index eventsOnEventNonce on events(createdByKeyCardId, eventNonce);
create unique index eventsOnShopSeq on events(createdByShopId, shopSeq);

CREATE TABLE payments (
    id            serial,
    orderId       bigint NOT NULL,
    shopId        bigint NOT NULL,
    shopSeqNo     bigint NOT NULL, -- the seqNo of shop when the order was finalized
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
    payedBlock  bytea,

    -- set if for e.g. a clerk cancels it or a variation was removed
    canceledAt    TIMESTAMP
);
alter table payments add constraint paymentIdLength check (octet_length(paymentId) = 32);
alter table payments add constraint erc20TokenAddrCheck check (erc20TokenAddr is null OR octet_length(erc20TokenAddr) = 20);
alter table payments add constraint paymentChosen check (paymentChosenAt is null OR (
    paymentId is NOT NULL OR
    purchaseAddr is NOT NULL OR
    chainId is NOT NULL OR
    lastBlockNo is NOT NULL OR
    coinsPayed  is NOT NULL OR
    coinsTotal  is NOT NULL
));
alter table payments add constraint paidHash check (payedAt is null or (
    payedTx is NOT NULL OR payedBlock is NOT NULL
));

CREATE UNIQUE INDEX paymentsOrderId ON payments (shopId, orderId);
CREATE INDEX paymentsOrderFinalizedAt ON payments (paymentChosenAt);
CREATE INDEX paymentsPayedAt ON payments (payedAt);
