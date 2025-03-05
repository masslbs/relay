--
-- PostgreSQL database dump
--

-- Dumped from database version 16.6
-- Dumped by pg_dump version 16.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: keycards; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.keycards (id, cardpublickey, userwalletaddr, shopid, linkedat, unlinkedat, lastackedseq, lastseenat, lastversion, isguest) FROM stdin;
2	\\x0335f040207427518bd287a23cba2ca54ee46c64dde7853595e81326ecb292e03c	\\xcf253e0a6fe4c38c7649815592fdcb3061808df0	1	2025-03-05 21:29:23.342323+01	\N	0	2025-03-05 21:29:23.354378+01	4	f
3	\\x03405b565cc773307a9d27412e9bec1abf3a3983c74cb983215d44a7ce2630940d	\\xdc955da1e557a235b45d33386ed2712b1473996a	1	2025-03-05 21:29:25.496825+01	\N	0	2025-03-05 21:29:25.50486+01	4	t
4	\\x023930e135584414ab79c50b8a8aaed7163bed2355bece961433831c08975b568c	\\xca5ea7fbe4060b3d723a25a22c2bea2e4a36138e	1	2025-03-05 21:29:27.213077+01	\N	0	2025-03-05 21:29:27.221401+01	4	t
\.


--
-- Data for Name: patchsets; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.patchsets (serverseq, keycardnonce, createdbykeycardid, createdbyshopid, shopseq, createdat, createdbynetworkschemaversion, receivedat, header, signature) FROM stdin;
1	1	1	\\x0000000000000001	1	2025-03-05 21:29:23.344096+01	4	2025-03-05 21:29:23.344187+01	\\xa46653686f7049440068526f6f74486173685820b2d3a03adbbdd239bec40e0c1da26f6769af9674a57ddbeccea4bdd1705990e66954696d657374616d70c07819323032352d30332d30355432313a32393a32332b30313a30306c4b6579436172644e6f6e636501	\\x9830ee3631961b6549656f864ce9ffb0c46794edc246491793d7dfa2f72185060563682175518335975d2a5c9d46326f57f3373262caace541eabcaf80ae5a7b01
2	1	2	\\x0000000000000001	2	2025-03-05 21:29:23+01	4	2025-03-05 21:29:23.677769+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858207a902b01cf8533663bf6728951ed3023756eafef73e0282419288f2266ebff1a6954696d657374616d70c074323032352d30332d30355432303a32393a32335a6c4b6579436172644e6f6e636501	\\x8e3cfca82b5fc8344817217603b480a8007c37ded0e0e109fa54b0b036708fd84c0b79f9825f261b82a109c3eb26667d9f56b68125267bb78a8a1f240364d73b01
3	2	2	\\x0000000000000001	3	2025-03-05 21:29:23+01	4	2025-03-05 21:29:23.866962+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f7448617368582056f9331031a2625255d221d622caee278efc009666e0a02c4b404f11d06e7aa56954696d657374616d70c074323032352d30332d30355432303a32393a32335a6c4b6579436172644e6f6e636502	\\xef085a14382386014dda0334f39ac5e020033db384938b293191abf0f11eec097ca52711f3ef0ca77f97a923f215b441731f1c05d57deac63ee91d60ab1a8b9801
4	3	2	\\x0000000000000001	4	2025-03-05 21:29:24+01	4	2025-03-05 21:29:24.068781+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858201cdfffb89b17d779fde4ac65f8707aece8ce7d3f1803c60a00a4b358378961266954696d657374616d70c074323032352d30332d30355432303a32393a32345a6c4b6579436172644e6f6e636503	\\x70836cc3579b11d0ce2bd292a699bb90e0be1af217df6f5a5064aa2dc82c9856503f3d50ca7eb3db3781f0ff01f43e2943fd969bd8c7bd245d3c11b2073cebc001
5	4	2	\\x0000000000000001	5	2025-03-05 21:29:24+01	4	2025-03-05 21:29:24.270185+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820e7d9c9934d38ae76af30e5f5f979e45dd809a89b5435fa89a4c0e07429fa66ad6954696d657374616d70c074323032352d30332d30355432303a32393a32345a6c4b6579436172644e6f6e636504	\\x608a63fff1029beb6bbe17334520d2f415a03f78022dd473fd3caa91cbab06a562fef9a3065055b939051a726b9cd5da78167df65c15c4fb16652f33d78a93f101
6	5	2	\\x0000000000000001	6	2025-03-05 21:29:24+01	4	2025-03-05 21:29:24.472669+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820aa7fe1f0f53b16b62c7b96dc0e075cc8265b87529b7988617d5cd4edb9ffc5bb6954696d657374616d70c074323032352d30332d30355432303a32393a32345a6c4b6579436172644e6f6e636505	\\xcb0b7dfb3335ddb7c9003900176f7fb7efae03b8c4545594de2e1b4a017892562ac2a26d972e319571edca27bac974dfd5b6157049102d67c85817bdad68a8a000
7	6	2	\\x0000000000000001	7	2025-03-05 21:29:24+01	4	2025-03-05 21:29:24.674218+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858205e5b590ed311a00b3966a6734a79925d7d4986eeb188f03569dd0ac002d451fb6954696d657374616d70c074323032352d30332d30355432303a32393a32345a6c4b6579436172644e6f6e636506	\\x89c4da50db225a30fd7174eb81253ed84630f8979f0ba2597c33fa25a48ceed1224c8b260ce1259258749ee79e964c5f754ebd520824c818efe4e3bf935b529501
8	7	2	\\x0000000000000001	8	2025-03-05 21:29:24+01	4	2025-03-05 21:29:24.875105+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820eefb03f7f9be4d48ce1e5336a901078c28bfe08288dba3fe3031929dad00cda76954696d657374616d70c074323032352d30332d30355432303a32393a32345a6c4b6579436172644e6f6e636507	\\xeb1ab81adbed452cf8af55076136c05e99c7ad24cb49e205ba1dfbcb5b7dc9450896acf60a39b6b1ec360061cc40fc91705d50944cd8a61f9cf31def5c8200e100
9	8	2	\\x0000000000000001	9	2025-03-05 21:29:25+01	4	2025-03-05 21:29:25.07741+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820fb6f64e8797e245ba5209117de6a40e641b7fe94ca05f27de2c4ac806effb08c6954696d657374616d70c074323032352d30332d30355432303a32393a32355a6c4b6579436172644e6f6e636508	\\x3b5c1fc1eb70a8d26b58650b468c651a2c2d8f0909255c42a4222dc65961a29b68be6ce9f135954b2fb119a9cc4f2943218ae7aff3718c562269e3824ea619c801
10	9	2	\\x0000000000000001	10	2025-03-05 21:29:25+01	4	2025-03-05 21:29:25.278864+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858205c4a89d2192e0301ff100550b9dd408f61181217aefafcdd9b31d3add1cf361b6954696d657374616d70c074323032352d30332d30355432303a32393a32355a6c4b6579436172644e6f6e636509	\\xde76367385833fa1d95398510fc9978e8d3433ff4425e66c73f55d5da7c60ab153e75ff2413bd6193ec93d2d352bea3220432db8e8a1722068972100f4fcc07800
11	2	1	\\x0000000000000001	11	2025-03-05 21:29:25.497035+01	4	2025-03-05 21:29:25.497109+01	\\xa46653686f7049440068526f6f7448617368582063c1a9b53827b4076cf5f0e3ecc9784c8777760dfab842b791e1b228d3654dc96954696d657374616d70c07819323032352d30332d30355432313a32393a32352b30313a30306c4b6579436172644e6f6e636502	\\x21a7a9506fd16ac517175795f8003676d9c0aa40eb6b2d4e0c9ec8438a1ce43c51526d763209ca020752f659bd78fb86fd21a8bd549ccadf7836fa0b5a7884fa00
12	1	3	\\x0000000000000001	12	2025-03-05 21:29:25+01	4	2025-03-05 21:29:25.826142+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858205c23765996ab89b5d054905cf6d31bf9cf0ae8e0d74156c6569c7967a6dd97cf6954696d657374616d70c074323032352d30332d30355432303a32393a32355a6c4b6579436172644e6f6e636501	\\xe76169eb303e82356a3b1d44de8f176a1094b992854c7d3a97a76d6694d6ff3a49925349acf31e63a78e0f73f1aa94fea1c0c0c2d6e82301570fce9f722525d401
13	2	3	\\x0000000000000001	13	2025-03-05 21:29:25+01	4	2025-03-05 21:29:25.98459+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858201737094736080655b325daee1ffb1aff296d4a385c172d243e10998c8f430b736954696d657374616d70c074323032352d30332d30355432303a32393a32355a6c4b6579436172644e6f6e636502	\\x3ec6d867015da3999119c822e4c408e47e45105d018521fdc1fb204dc74991c3693085a6437f994b08483c3c3512bac3c4d5ab0e79357443c5e6c36fe610848301
14	3	3	\\x0000000000000001	14	2025-03-05 21:29:26+01	4	2025-03-05 21:29:26.18693+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858202c8efaaabc6adaddb0d9f74d926dcf87cf3ee3d5f033ecca56a9eb0c2d14cca36954696d657374616d70c074323032352d30332d30355432303a32393a32365a6c4b6579436172644e6f6e636503	\\xcc88e2881ef04b66ca0c44eaef418e17d7365937e750003c9274eeaf1b5428293558724e93dd167598df34ab0c24b544fd429792e1d3eed5d298eb4e8c06d83a01
15	4	3	\\x0000000000000001	15	2025-03-05 21:29:26+01	4	2025-03-05 21:29:26.393225+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f7448617368582062d86a4c62b91bbcf744961ed0a0290de20af928dba6b787e62c616021ccd6e06954696d657374616d70c074323032352d30332d30355432303a32393a32365a6c4b6579436172644e6f6e636504	\\x6ac6c276fb9ad370f9979ca029dc3d7ed4cd7fcb8cb655074898ec351d1a27281bbfd0a391e2c940a082de6cfa4d2a83510ef9debdc22e48e9e071896bf7bb6501
16	5	3	\\x0000000000000001	16	2025-03-05 21:29:26+01	4	2025-03-05 21:29:26.591573+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858201f396ea791f34b4203d98725528e01ba445457d3dba81f0814545ecbece529166954696d657374616d70c074323032352d30332d30355432303a32393a32365a6c4b6579436172644e6f6e636505	\\xc3fe43ea4ebf39a13cf5e8e1ccaab29159680f9285c6e20ca6daa4eda67040277f9ceadee823b93ab3486c83dea5310e3eeb8c83d4cdb35406b6a3000cba4e9f00
17	6	3	\\x0000000000000001	17	2025-03-05 21:29:26+01	4	2025-03-05 21:29:26.793379+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f7448617368582088bcbee885e825516c483df4eba02a658ea02ca09ac2e91e78c3a585a1a13cf26954696d657374616d70c074323032352d30332d30355432303a32393a32365a6c4b6579436172644e6f6e636506	\\x4059978371510a39a394c1c79eb6135fc11c6b1e800faa38bf9d2255e7c65f2c47fb074ae7bb09db696aad72f384bc624f346d637149e39cc3030690e4695b8f00
18	7	3	\\x0000000000000001	18	2025-03-05 21:29:26+01	4	2025-03-05 21:29:26.998075+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820c8af35167a51a0280441ac97077cf41152c59d640b21b4e8b66d9f6b94b9f1f06954696d657374616d70c074323032352d30332d30355432303a32393a32365a6c4b6579436172644e6f6e636507	\\x3515e3854bc80bc2501b96ccabc5afcea0b4272458f3b04953cb005726cb62ba1615cd4895618fa0accffa75b3703b076ac0ea263dafd81c59cee8079074970e00
19	3	1	\\x0000000000000001	19	2025-03-05 21:29:27.213322+01	4	2025-03-05 21:29:27.21339+01	\\xa46653686f7049440068526f6f744861736858202e5bfb1fe0203362fcee7d649dbf0b75c0b4e65034c0338d61f1dad18cb2708c6954696d657374616d70c07819323032352d30332d30355432313a32393a32372b30313a30306c4b6579436172644e6f6e636503	\\xaaaf874d041ce4bed81bcb23eccde6c31b6da63b386f481e4f7e67a513758d66092bcac3d2f42d23e1613f48e7295b6b0cd2b5d27b3fb6ad8a76a6a2e1e8736800
20	1	4	\\x0000000000000001	20	2025-03-05 21:29:27+01	4	2025-03-05 21:29:27.551289+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820870c3e9a57f633b997ae692bc47575b1311c8902c2a14b4f47940d7a6a95c1996954696d657374616d70c074323032352d30332d30355432303a32393a32375a6c4b6579436172644e6f6e636501	\\x2aa909144bfe376e6090fdda2e0e81929f1659d1e0a7172a5f3016db2e0b20584a5ba5ec4b72d1499339e9f84af8c0c5aa758f6919b6df23d4bd6439c9a18ab801
21	2	4	\\x0000000000000001	21	2025-03-05 21:29:27+01	4	2025-03-05 21:29:27.703809+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f744861736858206e2f66facbbf26a3f8b0e0bbbe45f880b5d85e531ff3f421deb9d78965759cc76954696d657374616d70c074323032352d30332d30355432303a32393a32375a6c4b6579436172644e6f6e636502	\\x248922a239d7d2611db9c9b7317ebc90cd45e4be11cc20bd0636a564e812cc7a4f0813ab54452118417d02e92d94145d6dcaf4e580c9499e420cf01666cf921b01
22	3	4	\\x0000000000000001	22	2025-03-05 21:29:27+01	4	2025-03-05 21:29:27.908689+01	\\xa46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d18115468526f6f74486173685820cbb4f6c9ba72709635a4edd16547e5495f01f5f02fd7af848ac44161ece8e0176954696d657374616d70c074323032352d30332d30355432303a32393a32375a6c4b6579436172644e6f6e636503	\\x3c1a8acdf069fb02b7ba697e592c16d23d0511ea5ffa1127ca45876a23a1f6255e467226f761a78d3a572f263a2520e1ae12273421a4d7c3f507454794fddc6201
\.


--
-- Data for Name: patches; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.patches (patchsetserverseq, patchindex, encoded, mmrproof, op, objecttype, objectid, accountaddr, tagname) FROM stdin;
1	0	\\xa3624f70677265706c616365645061746881686d616e69666573746556616c7565a466506179656573a06653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d1811546f50726963696e6743757272656e6379a2674164647265737354000000000000000000000000000000000000000067436861696e4944197a6972416363657074656443757272656e63696573a0	\\x8300038158209b9497874c2f18ec02403b69218d77a92fc2fc21fab5d61b20c2fdde06805254	replace	manifest	\N	\N	\N
1	1	\\xa3624f7063616464645061746882676163636f756e7454cf253e0a6fe4c38c7649815592fdcb3061808df06556616c7565a2654775657374f4684b657943617264738158210335f040207427518bd287a23cba2ca54ee46c64dde7853595e81326ecb292e03c	\\x8301038158202d4a99f3a5f7faaac28d1daa939bfe2aebbb83138ccd2e2044d167f23ecceec7	add	account	\N	\\xcf253e0a6fe4c38c7649815592fdcb3061808df0	\N
2	0	\\xa3624f70677265706c616365645061746881686d616e69666573746556616c7565a566506179656573a1197a69a154cf253e0a6fe4c38c7649815592fdcb3061808df0a16e43616c6c4173436f6e7472616374f46653686f704944c258204ba708130505ddefa3e476fdec8f40eae3fc0e77781e4e61d85cdacd5d1811546f50726963696e6743757272656e6379a2674164647265737354000000000000000000000000000000000000000067436861696e4944197a696f5368697070696e67526567696f6e73a16764656661756c74a364436974796067436f756e7472796e49736c61206465204d75657274616a506f7374616c436f64656072416363657074656443757272656e63696573a1197a69a1540000000000000000000000000000000000000000a0	\\x830001f6	replace	manifest	\N	\N	\N
3	0	\\xa3624f7063616464645061746882676c697374696e671b6db881534801ead66556616c7565a46249441b6db881534801ead66550726963651907cf684d65746164617461a3655469746c6564426f6f6b66496d6167657381781d68747470733a2f2f6578616d706c652e636f6d2f696d6167652e706e676b4465736372697074696f6e7824546869732069732061206465736372697074696f6e206f6620746865206c697374696e676956696577537461746500	\\x830001f6	add	listing	\\x6db881534801ead6	\N	\N
4	0	\\xa3624f7069696e6372656d656e7464506174688269696e76656e746f72791b6db881534801ead66556616c75651864	\\x830001f6	increment	inventory	\\x6db881534801ead6	\N	\N
5	0	\\xa3624f7063616464645061746882676c697374696e671b755f9f94ff386dfb6556616c7565a46249441b755f9f94ff386dfb6550726963651909c3684d65746164617461a3655469746c6567542d536869727466496d6167657381781d68747470733a2f2f6578616d706c652e636f6d2f696d6167652e706e676b4465736372697074696f6e7824546869732069732061206465736372697074696f6e206f6620746865206c697374696e676956696577537461746500	\\x830001f6	add	listing	\\x755f9f94ff386dfb	\N	\N
6	0	\\xa3624f7069696e6372656d656e7464506174688269696e76656e746f72791b755f9f94ff386dfb6556616c7565185a	\\x830001f6	increment	inventory	\\x755f9f94ff386dfb	\N	\N
7	0	\\xa3624f7063616464645061746882676c697374696e671b91b7df1ab5e8c4716556616c7565a46249441b91b7df1ab5e8c4716550726963651905db684d65746164617461a3655469746c656a436f66666565204d756766496d6167657381781d68747470733a2f2f6578616d706c652e636f6d2f696d6167652e706e676b4465736372697074696f6e7824546869732069732061206465736372697074696f6e206f6620746865206c697374696e676956696577537461746500	\\x830001f6	add	listing	\\x91b7df1ab5e8c471	\N	\N
8	0	\\xa3624f7069696e6372656d656e7464506174688269696e76656e746f72791b91b7df1ab5e8c4716556616c75651850	\\x830001f6	increment	inventory	\\x91b7df1ab5e8c471	\N	\N
9	0	\\xa3624f7063616464645061746882676c697374696e671b03364406245037e06556616c7565a46249441b03364406245037e0655072696365190257684d65746164617461a3655469746c656c537469636b6572205061636b66496d6167657381781d68747470733a2f2f6578616d706c652e636f6d2f696d6167652e706e676b4465736372697074696f6e7824546869732069732061206465736372697074696f6e206f6620746865206c697374696e676956696577537461746500	\\x830001f6	add	listing	\\x03364406245037e0	\N	\N
10	0	\\xa3624f7069696e6372656d656e7464506174688269696e76656e746f72791b03364406245037e06556616c75651846	\\x830001f6	increment	inventory	\\x03364406245037e0	\N	\N
11	0	\\xa3624f7063616464645061746882676163636f756e7454dc955da1e557a235b45d33386ed2712b1473996a6556616c7565a2654775657374f5684b6579436172647381582103405b565cc773307a9d27412e9bec1abf3a3983c74cb983215d44a7ce2630940d	\\x830001f6	add	account	\N	\\xdc955da1e557a235b45d33386ed2712b1473996a	\N
12	0	\\xa3624f7063616464645061746882656f726465721bf61aaf33264fc94b6556616c7565a36249441bf61aaf33264fc94b654974656d738065537461746501	\\x830001f6	add	order	\\xf61aaf33264fc94b	\N	\N
13	0	\\xa3624f7063616464645061746884656f726465721bf61aaf33264fc94b656974656d73612d6556616c7565a2685175616e7469747902694c697374696e6749441b6db881534801ead6	\\x830001f6	add	order	\\xf61aaf33264fc94b	\N	\N
14	0	\\xa3624f7063616464645061746884656f726465721bf61aaf33264fc94b656974656d73612d6556616c7565a2685175616e7469747901694c697374696e6749441b755f9f94ff386dfb	\\x830001f6	add	order	\\xf61aaf33264fc94b	\N	\N
15	0	\\xa3624f70677265706c616365645061746883656f726465721bf61aaf33264fc94b6573746174656556616c756503	\\x830001f6	replace	order	\\xf61aaf33264fc94b	\N	\N
16	0	\\xa3624f7063616464645061746882656f726465721b578b994ee25194df6556616c7565a36249441b578b994ee25194df654974656d738065537461746501	\\x830001f6	add	order	\\x578b994ee25194df	\N	\N
17	0	\\xa3624f7063616464645061746884656f726465721b578b994ee25194df656974656d73612d6556616c7565a2685175616e7469747903694c697374696e6749441b91b7df1ab5e8c471	\\x830001f6	add	order	\\x578b994ee25194df	\N	\N
18	0	\\xa3624f70677265706c616365645061746883656f726465721b578b994ee25194df6573746174656556616c756503	\\x830001f6	replace	order	\\x578b994ee25194df	\N	\N
19	0	\\xa3624f7063616464645061746882676163636f756e7454ca5ea7fbe4060b3d723a25a22c2bea2e4a36138e6556616c7565a2654775657374f5684b65794361726473815821023930e135584414ab79c50b8a8aaed7163bed2355bece961433831c08975b568c	\\x830001f6	add	account	\N	\\xca5ea7fbe4060b3d723a25a22c2bea2e4a36138e	\N
20	0	\\xa3624f7063616464645061746882656f726465721b6f2ff8dd7ed408666556616c7565a36249441b6f2ff8dd7ed40866654974656d738065537461746501	\\x830001f6	add	order	\\x6f2ff8dd7ed40866	\N	\N
21	0	\\xa3624f7063616464645061746884656f726465721b6f2ff8dd7ed40866656974656d73612d6556616c7565a2685175616e7469747905694c697374696e6749441b03364406245037e0	\\x830001f6	add	order	\\x6f2ff8dd7ed40866	\N	\N
22	0	\\xa3624f70677265706c616365645061746883656f726465721b6f2ff8dd7ed408666573746174656556616c756503	\\x830001f6	replace	order	\\x6f2ff8dd7ed40866	\N	\N
\.


--
-- Data for Name: payments; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.payments (id, orderid, shopid, shopseqno, itemslockedat, paymentchosenat, paymentid, purchaseaddr, chainid, lastblockno, coinstotal, erc20tokenaddr, payedat, payedtx, payedblock, canceledat) FROM stdin;
1	\\xf61aaf33264fc94b	\\x0000000000000001	14	2025-03-05 21:29:26.390996	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N
2	\\x578b994ee25194df	\\x0000000000000001	17	2025-03-05 21:29:26.996068	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N
3	\\x6f2ff8dd7ed40866	\\x0000000000000001	21	2025-03-05 21:29:27.906496	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N
\.


--
-- Data for Name: relaykeycards; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.relaykeycards (id, shopid, cardpublickey, lastusedat, lastwritteneventnonce) FROM stdin;
1	1	\\x023255458e24278e31d5940f304b16300fdff3f6efd3e2a030b5818310ac67af45	2025-03-05 21:29:27.213077+01	3
\.


--
-- Data for Name: shops; Type: TABLE DATA; Schema: public; Owner: cryptix
--

COPY public.shops (id, tokenid, createdat) FROM stdin;
1	34218582830301705288005342661105637224937311332703590839272725584231924240724	2025-03-05 21:29:23.342323+01
\.


--
-- Name: keycardidseq; Type: SEQUENCE SET; Schema: public; Owner: cryptix
--

SELECT pg_catalog.setval('public.keycardidseq', 4, true);


--
-- Name: payments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cryptix
--

SELECT pg_catalog.setval('public.payments_id_seq', 3, true);


--
-- Name: shops_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cryptix
--

SELECT pg_catalog.setval('public.shops_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--

