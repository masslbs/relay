begin;

create table shopStateData (
    shopId bigint NOT NULL primary key,
    shopSeq bigint NOT NULL,
    rootHash bytea NOT NULL,
    stateData bytea NOT NULL);

create unique index shopStateDataOnShopIdAndShopSeq on shopStateData(shopId,shopSeq);

commit;