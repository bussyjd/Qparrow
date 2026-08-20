create table btqMasterSecret (id identity not null, secret varbinary(64), initialisationVector varbinary(32), encryptedBytes varbinary(255), keySalt varbinary(32), deriver integer, crypter integer);
alter table keystore add column btqMasterSecret bigint;
alter table keystore add constraint keystore_btqMasterSecret_unique unique (btqMasterSecret);
alter table keystore add constraint keystore_btqMasterSecret foreign key (btqMasterSecret) references btqMasterSecret;
