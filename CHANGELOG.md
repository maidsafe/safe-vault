# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.44.1](https://github.com/maidsafe/sn_node/compare/v0.44.0...v0.44.1) (2021-05-25)

## [0.44.0](https://github.com/maidsafe/sn_node/compare/v0.43.6...v0.44.0) (2021-05-24)


### ⚠ BREAKING CHANGES

* **client-msgs:** using a non-backward compatible version of sn_messaging

### Features

* **client-msgs:** adapt to changes to client messages to receive client signature in each message ([0432987](https://github.com/maidsafe/sn_node/commit/043298714e70919fde269c462fcb009b6ef4cdd3))

### [0.43.6](https://github.com/maidsafe/sn_node/compare/v0.43.5...v0.43.6) (2021-05-22)

### [0.43.5](https://github.com/maidsafe/sn_node/compare/v0.43.4...v0.43.5) (2021-05-21)

### [0.43.4](https://github.com/maidsafe/sn_node/compare/v0.43.3...v0.43.4) (2021-05-20)


### Bug Fixes

* **adult-liveliness:** hold only node addresses for write liveliness ([fd019b5](https://github.com/maidsafe/sn_node/commit/fd019b5205f9af545aa16d18a338921ae10aaa08))

### [0.43.3](https://github.com/maidsafe/sn_node/compare/v0.43.2...v0.43.3) (2021-05-20)

### [0.43.2](https://github.com/maidsafe/sn_node/compare/v0.43.1...v0.43.2) (2021-05-19)


### Bug Fixes

* changes according to latest code, plus some clippy and fmt fixes ([dae49ee](https://github.com/maidsafe/sn_node/commit/dae49ee5b65b654e255642992cfd8e79f79eb608))

### [0.43.1](https://github.com/maidsafe/sn_node/compare/v0.43.0...v0.43.1) (2021-05-17)


### Bug Fixes

* **blob:** don't mark Blob responses for aggregation at destination ([a4efe5b](https://github.com/maidsafe/sn_node/commit/a4efe5b060879da7c7459d1a6fc6e417429a2cc0))

## [0.43.0](https://github.com/maidsafe/sn_node/compare/v0.42.7...v0.43.0) (2021-05-13)


### ⚠ BREAKING CHANGES

* Messaging dep update.

### Features

* add SupportingInfo message support ([74d1c9f](https://github.com/maidsafe/sn_node/commit/74d1c9f763bbd00e92e0dd1f002b7b4f75207297))
* handle sending + receiving updated section wallet history ([fe4327d](https://github.com/maidsafe/sn_node/commit/fe4327d0e3feb5011267e9d3eda570028ecf504f))
* Initital set up for some lazy message sending ([a29b16c](https://github.com/maidsafe/sn_node/commit/a29b16ce13199dd05ff6e5d6f0ba490c97de5d25))
* **adult_ops:** compute new holders for chunks and republish them on ([ce8d9e5](https://github.com/maidsafe/sn_node/commit/ce8d9e5b0e808fe8b8a1143d4674e09b8265d541))
* **data-organisation:** republish data on AdultsChanged events ([d4289f0](https://github.com/maidsafe/sn_node/commit/d4289f05b43b5efb8d74505ba058e806625c70f3))


### Bug Fixes

* cleanup and PR comments ([125806a](https://github.com/maidsafe/sn_node/commit/125806aac6f1b275b67af76fdf631b7036d092b8))
* multiple fixes and rebase atop T5 ([a2c56bc](https://github.com/maidsafe/sn_node/commit/a2c56bcdfc1da1c4f37edc4b4c158b2d632dce5c))
* **AE:** rebase fixes of AE atop T4.2 ([ac8a030](https://github.com/maidsafe/sn_node/commit/ac8a0304f20567b67eca5a0b57bd73fb86961d82))
* **blob-storage:** handle edge-cases when republishing Blob data ([e596869](https://github.com/maidsafe/sn_node/commit/e596869cf97cd44731a37d73b3e7dfd1b9de7434))
* **error-handling:** return a message to the sender when any error was encountered ([1327cc2](https://github.com/maidsafe/sn_node/commit/1327cc264986b9ab52ea7d8f4be4d19831b6acb8))
* post-rebase issues ([2bedd59](https://github.com/maidsafe/sn_node/commit/2bedd59cbc31932f0bed264ae35c43f891e8ba7b))
* **messaging:** only try get section key when to aggregate ([28a5bda](https://github.com/maidsafe/sn_node/commit/28a5bda17a6125003e8624e91dde8467818293de))


* messaging dep updates for ProcessMsg ([7935639](https://github.com/maidsafe/sn_node/commit/79356390e8640fe881fedfb56c4a5403c7cc6b8f))

### [0.42.7](https://github.com/maidsafe/sn_node/compare/v0.42.6...v0.42.7) (2021-05-12)

### [0.42.6](https://github.com/maidsafe/sn_node/compare/v0.42.5...v0.42.6) (2021-05-11)


### Bug Fixes

* **chunk-ops:** respond back to clients with an error when adults are ([4c10c17](https://github.com/maidsafe/sn_node/commit/4c10c17f38b0fcdd4f9751631f1c1843e939eaff))

### [0.42.5](https://github.com/maidsafe/sn_node/compare/v0.42.4...v0.42.5) (2021-05-11)


### Bug Fixes

* **adult-tracking:** misc. fixes for republishing data and tracking adult responsiveness ([4c931be](https://github.com/maidsafe/sn_node/commit/4c931beb6faa994a2d54f2dcc29b5818d37d1026))
* **storage:** do storage checks on writes at adults as well ([42b9b78](https://github.com/maidsafe/sn_node/commit/42b9b78007b6c87edc64443e6a5410fd8ccacd42))

### [0.42.4](https://github.com/maidsafe/sn_node/compare/v0.42.3...v0.42.4) (2021-05-10)

### [0.42.3](https://github.com/maidsafe/sn_node/compare/v0.42.2...v0.42.3) (2021-05-10)

### [0.42.2](https://github.com/maidsafe/sn_node/compare/v0.42.1...v0.42.2) (2021-05-10)

### [0.42.1](https://github.com/maidsafe/sn_node/compare/v0.42.0...v0.42.1) (2021-05-06)


### Bug Fixes

* **section_funds:** fix unfinished loop when dropping wallets ([bae1cc9](https://github.com/maidsafe/sn_node/commit/bae1cc9d461cd5240b0abff9d4fad0cbd0fb8954))

## [0.42.0](https://github.com/maidsafe/sn_node/compare/v0.41.2...v0.42.0) (2021-05-06)


### ⚠ BREAKING CHANGES

* **store_cost:** Updated sn_messaging query response api.

### Features

* **store_cost:** return section key and bytes on query ([dd12653](https://github.com/maidsafe/sn_node/commit/dd12653424b8f46d8269c971f22a684ef308e002))

### [0.41.2](https://github.com/maidsafe/sn_node/compare/v0.41.1...v0.41.2) (2021-05-06)


### Bug Fixes

* **replication:** copy and filter data before clearing ([5d6b110](https://github.com/maidsafe/sn_node/commit/5d6b11008dbd464a1622ae4d6d2330b6d0761aae))

### [0.41.1](https://github.com/maidsafe/sn_node/compare/v0.41.0...v0.41.1) (2021-05-05)


### Features

* **chunks:** don't return an error when trying to write a private chunk which already exists ([83f5063](https://github.com/maidsafe/sn_node/commit/83f50637b605679b601d9ea5ea44752ffb84b077))

## [0.41.0](https://github.com/maidsafe/sn_node/compare/v0.40.3...v0.41.0) (2021-05-04)


### ⚠ BREAKING CHANGES

* **chunk-org:** updates to sn_messaging 20.0.0 and sn_routing 0.65.0

### Features

* **adult_ops:** compute new holders for chunks and republish them on ([75e5c6e](https://github.com/maidsafe/sn_node/commit/75e5c6e568f84f9fc603346eaa77766b31a8496e))
* **chunk-org:** track adult liveliness for republishing of data too ([6e2eca5](https://github.com/maidsafe/sn_node/commit/6e2eca5142c0581fc95489446bd2c1030451dbd6))
* **chunk-storage:** use CHUNK_COPY_COUNT when checking condition for ([667cf91](https://github.com/maidsafe/sn_node/commit/667cf91952a0212751def033c86a27f233862d82))
* **data-organisation:** republish data on AdultsChanged events ([6aea15d](https://github.com/maidsafe/sn_node/commit/6aea15d719536cdf5764ad58b9af57eb8a8adaa0))


### Bug Fixes

* **blob-storage:** handle edge-cases when republishing Blob data ([aadffef](https://github.com/maidsafe/sn_node/commit/aadffef59ed36928a446fbe4cc5c0629475eab18))
* **chunk_storage:** exclude full adults while computing closest adults ([9069b3f](https://github.com/maidsafe/sn_node/commit/9069b3fe97675eed3f45ecd179ddf9699897f5f8))
* **chunk-ops:** propagate errors back if the blob-write was client ([7ced9d8](https://github.com/maidsafe/sn_node/commit/7ced9d863037d29de21be57cd759e9980c4df4a6))

### [0.40.3](https://github.com/maidsafe/sn_node/compare/v0.40.2...v0.40.3) (2021-04-30)

### [0.40.2](https://github.com/maidsafe/sn_node/compare/v0.40.1...v0.40.2) (2021-04-29)

### [0.40.1](https://github.com/maidsafe/sn_node/compare/v0.40.0...v0.40.1) (2021-04-29)


### Bug Fixes

* **chunk:** remove message aggregation for Chunks queries ([20dd687](https://github.com/maidsafe/sn_node/commit/20dd6872e68e2ae42ce3a7a7e15f0bc2bb59df37))

## [0.40.0](https://github.com/maidsafe/sn_node/compare/v0.39.2...v0.40.0) (2021-04-28)


### ⚠ BREAKING CHANGES

* **err:** updates to sn_messaging 19.0.0 and sn_data_types 0.18.3
and sn_routing 0.64.0

* **err:** return chunk address along with DataNotFound error ([74e2b3e](https://github.com/maidsafe/sn_node/commit/74e2b3e73ab1a3100c4794ea048d66bd416883a1))

### [0.39.2](https://github.com/maidsafe/sn_node/compare/v0.39.1...v0.39.2) (2021-04-27)

### [0.39.1](https://github.com/maidsafe/sn_node/compare/v0.39.0...v0.39.1) (2021-04-26)


### Features

* **chunks:** restore reg of liveness with queryresponse ([e11898d](https://github.com/maidsafe/sn_node/commit/e11898dc76a3c15b5b5565e72dceb2e7a8312904))

## [0.39.0](https://github.com/maidsafe/sn_node/compare/v0.38.10...v0.39.0) (2021-04-23)


### ⚠ BREAKING CHANGES

* **queries:** `NodeCmdResult` removed from `Message` enum.

### Bug Fixes

* **queries:** restore client as recipient of chunk query response ([113daee](https://github.com/maidsafe/sn_node/commit/113daee9f8551a4c5a2c50c2eafb3c8a7a873dae))

### [0.38.10](https://github.com/maidsafe/sn_node/compare/v0.38.9...v0.38.10) (2021-04-23)

### [0.38.9](https://github.com/maidsafe/sn_node/compare/v0.38.8...v0.38.9) (2021-04-23)


### Bug Fixes

* **capacity:** allow joins after split ([45fc453](https://github.com/maidsafe/sn_node/commit/45fc453817894e430051eb9a81dba7d94ecbf369))

### [0.38.8](https://github.com/maidsafe/sn_node/compare/v0.38.7...v0.38.8) (2021-04-23)


### Bug Fixes

* **storecost:** storecost always at least 1 ([df887e3](https://github.com/maidsafe/sn_node/commit/df887e3eb46b00cf023ad5929ac5cfba20fbd50e))

### [0.38.7](https://github.com/maidsafe/sn_node/compare/v0.38.6...v0.38.7) (2021-04-23)

### [0.38.6](https://github.com/maidsafe/sn_node/compare/v0.38.5...v0.38.6) (2021-04-23)

### [0.38.5](https://github.com/maidsafe/sn_node/compare/v0.38.4...v0.38.5) (2021-04-22)


### Bug Fixes

* **metadata:** stop tracking adults when promoted ([44a4a19](https://github.com/maidsafe/sn_node/commit/44a4a19b64443bb210127af6ff38a83414a155f5))

### [0.38.4](https://github.com/maidsafe/sn_node/compare/v0.38.3...v0.38.4) (2021-04-22)

### [0.38.3](https://github.com/maidsafe/sn_node/compare/v0.38.2...v0.38.3) (2021-04-22)


### Bug Fixes

* **data_section:** remove offline nodes from the pending adult ([63498b6](https://github.com/maidsafe/sn_node/commit/63498b6e0e131adea4cf56b4c591b4bff8c36ec2))

### [0.38.2](https://github.com/maidsafe/sn_node/compare/v0.38.1...v0.38.2) (2021-04-21)

### [0.38.1](https://github.com/maidsafe/sn_node/compare/v0.38.0...v0.38.1) (2021-04-21)


### Bug Fixes

* **adult_ops:** avoid underflowing decrement ([896e6b0](https://github.com/maidsafe/sn_node/commit/896e6b00db5377b610c7f0946e25cdcb8d75cc3d))

## [0.38.0](https://github.com/maidsafe/sn_node/compare/v0.37.14...v0.38.0) (2021-04-21)


### ⚠ BREAKING CHANGES

* **data_sync:** sn_messaging and sn_routing breaking changes.

* **data_sync:** follow up PR to the data loss PR ([2cb863f](https://github.com/maidsafe/sn_node/commit/2cb863f271ef33655ebe752b6156f2cd40d2d74e))

### [0.37.14](https://github.com/maidsafe/sn_node/compare/v0.37.13...v0.37.14) (2021-04-21)


### Features

* **storage:** changes to support the new Register data type in storage ([717bb01](https://github.com/maidsafe/sn_node/commit/717bb012539de0e1cf0a1f48e5a87bab3c623248))

### [0.37.13](https://github.com/maidsafe/sn_node/compare/v0.37.12...v0.37.13) (2021-04-21)


### Features

* **data:** share data on churn to New Elders ([8b101d9](https://github.com/maidsafe/sn_node/commit/8b101d9496375403f0803ec9c55db90d8ede9c9d))


### Bug Fixes

* **data:** multiple fixes on usage of chunkstore and sharing of data ([ae12c29](https://github.com/maidsafe/sn_node/commit/ae12c29f7cdfd29faa4500a5616b00de31aa4d4d))
* **data:** skip data sharing on network startup ([a6a6beb](https://github.com/maidsafe/sn_node/commit/a6a6beb30c1a2662d914a05f96d4eb98ebd1f33c))
* **full_nodes:** retain members only on full_node db during splits and churns ([2ff4ff8](https://github.com/maidsafe/sn_node/commit/2ff4ff8c93631adb823ac5539e6545615f03c17d))

### [0.37.12](https://github.com/maidsafe/sn_node/compare/v0.37.11...v0.37.12) (2021-04-21)


### Features

* **data_section:** propose unresponsive Adult as offline using Routing ([339dd13](https://github.com/maidsafe/sn_node/commit/339dd1370bb3eeb6da0aef19c09b7dcb4c80ca5b)), closes [#1433](https://github.com/maidsafe/sn_node/issues/1433)

### [0.37.11](https://github.com/maidsafe/sn_node/compare/v0.37.10...v0.37.11) (2021-04-21)


### Features

* **data_section:** track responsiveness of Adults to data requests so ([bcad135](https://github.com/maidsafe/sn_node/commit/bcad135bfaa85851a04ab8dc1613ef2964b9179f))

### [0.37.10](https://github.com/maidsafe/sn_node/compare/v0.37.9...v0.37.10) (2021-04-21)


### Bug Fixes

* remove duplicate cargo.lock version line ([e749a5f](https://github.com/maidsafe/sn_node/commit/e749a5f2dc342e0ad484607d85d719fb4cbbe939))

### [0.37.9](https://github.com/maidsafe/sn_node/compare/v0.37.8...v0.37.9) (2021-04-21)


### Features

* write network keypair to disk ([ad4c3ab](https://github.com/maidsafe/sn_node/commit/ad4c3ab2df7379e199bd1b1f53161321fe2e5af0))

### [0.37.8](https://github.com/maidsafe/sn_node/compare/v0.37.7...v0.37.8) (2021-04-15)

### [0.37.7](https://github.com/maidsafe/sn_node/compare/v0.37.6...v0.37.7) (2021-04-14)

### [0.37.6](https://github.com/maidsafe/sn_node/compare/v0.37.5...v0.37.6) (2021-04-14)

### [0.37.5](https://github.com/maidsafe/sn_node/compare/v0.37.4...v0.37.5) (2021-04-14)


### Bug Fixes

* change stack size to 8mb for all windows builds ([27b4c4e](https://github.com/maidsafe/sn_node/commit/27b4c4ea9b3d37bb947961229c3b29e48b014586))

### [0.37.4](https://github.com/maidsafe/sn_node/compare/v0.37.3...v0.37.4) (2021-04-14)


### Bug Fixes

* do not overwrite existing reward key ([eee066b](https://github.com/maidsafe/sn_node/commit/eee066b3b300162deabff1bf48958713fbb3fb0d))

### [0.37.3](https://github.com/maidsafe/sn_node/compare/v0.37.2...v0.37.3) (2021-04-14)

### [0.37.2](https://github.com/maidsafe/sn_node/compare/v0.37.1...v0.37.2) (2021-04-14)

### [0.37.1](https://github.com/maidsafe/sn_node/compare/v0.37.0...v0.37.1) (2021-04-14)

## [0.37.0](https://github.com/maidsafe/sn_node/compare/v0.36.2...v0.37.0) (2021-04-13)


### ⚠ BREAKING CHANGES

* **deps:** Members of node cmds changed.

### Bug Fixes

* **msgs:** add aggregation scheme to SendToNodes ([ca19c7d](https://github.com/maidsafe/sn_node/commit/ca19c7d8dec0b4b89dd24f923a8d3cac4092de27))


* **deps:** update sn_messaging and sn_routing ([0913819](https://github.com/maidsafe/sn_node/commit/09138195c2ca3f5962a351bfbaa0268d07ac2132))

### [0.36.2](https://github.com/maidsafe/sn_node/compare/v0.36.1...v0.36.2) (2021-04-13)


### Bug Fixes

* post-rebase issues + clippy ([dffd5c3](https://github.com/maidsafe/sn_node/commit/dffd5c332ad3fc7658c1744b8359812a34456943))

### [0.36.1](https://github.com/maidsafe/sn_node/compare/v0.36.0...v0.36.1) (2021-04-13)

## [0.36.0](https://github.com/maidsafe/sn_node/compare/v0.35.7...v0.36.0) (2021-04-13)


### ⚠ BREAKING CHANGES

* **deps:** sn_routing major version bump
* **join:** this updates to the latest version of routing and qp2p
which have breaking changes

### Bug Fixes

* **join:** automatic retry when RoutingError::TryJoinLater is ([3ce6180](https://github.com/maidsafe/sn_node/commit/3ce6180785ac110557a143fc2100649c78acbb49))


* **deps:** cargo update ([ccc5e19](https://github.com/maidsafe/sn_node/commit/ccc5e191a5671659583e25c172876fd69192a620))

### [0.35.7](https://github.com/maidsafe/sn_node/compare/v0.35.6...v0.35.7) (2021-04-13)

### [0.35.6](https://github.com/maidsafe/sn_node/compare/v0.35.5...v0.35.6) (2021-04-13)

### [0.35.5](https://github.com/maidsafe/sn_node/compare/v0.35.4...v0.35.5) (2021-04-12)


### Features

* **chunks:** report full when at 50% ([23e1fdb](https://github.com/maidsafe/sn_node/commit/23e1fdb56baa5b2ba703b1f88ac6c22787d37308))

### [0.35.4](https://github.com/maidsafe/sn_node/compare/v0.35.3...v0.35.4) (2021-04-12)


### Bug Fixes

* **replication:** update holders ([aff4370](https://github.com/maidsafe/sn_node/commit/aff4370746e851bd27c6d504485e238388ee5eb1))

### [0.35.3](https://github.com/maidsafe/sn_node/compare/v0.35.2...v0.35.3) (2021-04-12)

### [0.35.2](https://github.com/maidsafe/sn_node/compare/v0.35.1...v0.35.2) (2021-04-09)

### [0.35.1](https://github.com/maidsafe/sn_node/compare/v0.35.0...v0.35.1) (2021-04-08)

## [0.35.0](https://github.com/maidsafe/sn_node/compare/v0.34.10...v0.35.0) (2021-04-08)


### ⚠ BREAKING CHANGES

* **deps:** new version of sn_messaging
- This removes the unused `AtSource` aggregation scheme.

* **deps:** update sn_messaging ([d75c343](https://github.com/maidsafe/sn_node/commit/d75c343099e2c864bcc54aaaa73f53d639dc2ae7))

### [0.34.10](https://github.com/maidsafe/sn_node/compare/v0.34.9...v0.34.10) (2021-04-08)

### [0.34.9](https://github.com/maidsafe/sn_node/compare/v0.34.8...v0.34.9) (2021-04-08)


### Bug Fixes

* **chunks:** add in missing capacity reached check ([2da76af](https://github.com/maidsafe/sn_node/commit/2da76af4fb375b409159115fd263e9e0977f3fe7))

### [0.34.8](https://github.com/maidsafe/sn_node/compare/v0.34.7...v0.34.8) (2021-04-08)


### Bug Fixes

* **rewards:** improve distribution ([4927633](https://github.com/maidsafe/sn_node/commit/492763350d68ef34abea8c019f0a1541523788df))

### [0.34.7](https://github.com/maidsafe/sn_node/compare/v0.34.6...v0.34.7) (2021-04-07)


### Features

* **joining:** open for new joins when nodes leave ([b307730](https://github.com/maidsafe/sn_node/commit/b307730a8cc4e50a906c6148f48166480c282b5f))

### [0.34.6](https://github.com/maidsafe/sn_node/compare/v0.34.5...v0.34.6) (2021-04-07)


### Features

* **joins:** enable limiting joins again ([328b8d4](https://github.com/maidsafe/sn_node/commit/328b8d45b9ae9002017d9dff4e562934953946f7))

### [0.34.5](https://github.com/maidsafe/sn_node/compare/v0.34.4...v0.34.5) (2021-04-07)


### Bug Fixes

* **config:** set connection info when genesis ([9857435](https://github.com/maidsafe/sn_node/commit/9857435f96e9fae834d96cd0be717efdb3b5210b))

### [0.34.4](https://github.com/maidsafe/sn_node/compare/v0.34.3...v0.34.4) (2021-04-07)


### Features

* **launch_network:** use NODE_COUNT env variable to set number of nodes ([aff6d4e](https://github.com/maidsafe/sn_node/commit/aff6d4eb19cc1be99a18ef1f2d90071a8efce8ff))

### [0.34.3](https://github.com/maidsafe/sn_node/compare/v0.34.2...v0.34.3) (2021-04-06)


### Bug Fixes

* **rewards:** distribute according to work ([62ff7dc](https://github.com/maidsafe/sn_node/commit/62ff7dca6dcc5cb722287d7bb716f7b6229de243))

### [0.34.2](https://github.com/maidsafe/sn_node/compare/v0.34.1...v0.34.2) (2021-04-06)


### Bug Fixes

* **propagation:** rely on routing aggregation ([f9840a3](https://github.com/maidsafe/sn_node/commit/f9840a324d3714035afa2159303d1dfb0480160a))

### [0.34.1](https://github.com/maidsafe/sn_node/compare/v0.34.0...v0.34.1) (2021-04-06)


### Features

* **local_network:** connect to random elder ([21cd191](https://github.com/maidsafe/sn_node/commit/21cd1917c7facab19c80eac6daa679fea1d5830c))

## [0.34.0](https://github.com/maidsafe/sn_node/compare/v0.33.5...v0.34.0) (2021-04-06)


### ⚠ BREAKING CHANGES

* **config:** this changes the fields of the node configuration

* **config:** refactor command line arguments to improve user ([11850c8](https://github.com/maidsafe/sn_node/commit/11850c8b4a9607ed8d9b07b6758aa84cb4678966))

### [0.33.5](https://github.com/maidsafe/sn_node/compare/v0.33.4...v0.33.5) (2021-04-02)


### Bug Fixes

* unimplemented error handling of transfer error ([e21aa51](https://github.com/maidsafe/sn_node/commit/e21aa51f4aea36c3a5afcb276c4a373b8a032a85))
* **rewards:** sync wallets in a better way ([090344f](https://github.com/maidsafe/sn_node/commit/090344fe089248c508587773e1d41ab2a5cc4607))

### [0.33.4](https://github.com/maidsafe/sn_node/compare/v0.33.3...v0.33.4) (2021-04-02)


### Bug Fixes

* use routing 0.57 for qp2p wan fixes ([e08dde7](https://github.com/maidsafe/sn_node/commit/e08dde78e5b727e0c9a7162b64f2021e6983457c))

### [0.33.3](https://github.com/maidsafe/sn_node/compare/v0.33.2...v0.33.3) (2021-04-01)


### Features

* **rewards:** limit supply ([1dae6c2](https://github.com/maidsafe/sn_node/commit/1dae6c24edeedce94703a715a3f6aa97304e3eb1))

### [0.33.2](https://github.com/maidsafe/sn_node/compare/v0.33.1...v0.33.2) (2021-04-01)


### Bug Fixes

* **transfers:** update replica info on churn ([a052cd6](https://github.com/maidsafe/sn_node/commit/a052cd6f53e3a5ccff66cfdd146cf4032d211da4))

### [0.33.1](https://github.com/maidsafe/sn_node/compare/v0.33.0...v0.33.1) (2021-04-01)


### Features

* **errors:** add specific errors ([9ba436c](https://github.com/maidsafe/sn_node/commit/9ba436c701b8fd38cf9f17ee6e9476611d65be84))

## [0.33.0](https://github.com/maidsafe/sn_node/compare/v0.32.0...v0.33.0) (2021-03-31)


### ⚠ BREAKING CHANGES

* **config:** this commit changes some fields in the node config

### Features

* **config:** rename local config to loopback and add lan option ([9e6a83d](https://github.com/maidsafe/sn_node/commit/9e6a83d143b16b320b6deaca9f68558d6bafe48b))

## [0.32.0](https://github.com/maidsafe/sn_node/compare/v0.31.1...v0.32.0) (2021-03-31)


### ⚠ BREAKING CHANGES

* **deps:** Reward flow overhaul

### Features

* **payment:** add payment to section funds ([3383e2d](https://github.com/maidsafe/sn_node/commit/3383e2d5d216ad124dde9b7dad768298f0e286f2))
* **rewards:** distribute to many based on age ([230ec03](https://github.com/maidsafe/sn_node/commit/230ec03ca9af7ad3e0b8ef71cb700fe8e080a964))
* **rewards:** mint and reward at churn ([4ff05c4](https://github.com/maidsafe/sn_node/commit/4ff05c47bd3fa53f43dd28696f13c218c3f7f509))
* **section_funds:** remove section wallet ([2d48ce2](https://github.com/maidsafe/sn_node/commit/2d48ce2775b3b5364e01bd44c722ea3f0e79f233))
* **tokens:** add the actual minting of new tokens ([d885117](https://github.com/maidsafe/sn_node/commit/d885117b6ce1d4cd074a77d92da27be181312595))


### Bug Fixes

* post-rebase issues ([1350573](https://github.com/maidsafe/sn_node/commit/13505732ab1911a53ec08f48a88c1447e66f2b67))
* propagate only once per wallet churn ([f072e89](https://github.com/maidsafe/sn_node/commit/f072e891e71a3374db84be6556edebcd54c2850e))
* send register payout to section instead of nodes ([fc6ed33](https://github.com/maidsafe/sn_node/commit/fc6ed33cb67cf007fba31f2f028274132d2ea87a))


* **deps:** update sn_routing ([ddaa1ce](https://github.com/maidsafe/sn_node/commit/ddaa1ce618ad2fd8f7ce76a49d01196011f4aa23))

### [0.31.1](https://github.com/maidsafe/sn_node/compare/v0.31.0...v0.31.1) (2021-03-31)

## [0.31.0](https://github.com/maidsafe/sn_node/compare/v0.30.0...v0.31.0) (2021-03-23)


### ⚠ BREAKING CHANGES

* messaging and DT udpates
* **accumulation:** this changes uses a new version of sn_messaging with a
breaking change
* **messaging:** new version of sn_messaging includes a breaking change

### Features

* add get balance handling ([75cfeb0](https://github.com/maidsafe/sn_node/commit/75cfeb03f2c181372bcec8e53f8acab81488d4ec))
* can register transfers again ([30156c5](https://github.com/maidsafe/sn_node/commit/30156c52ca1a54d96cf6481077109d803e1c0ff3))
* enable client section payout and history query of balance ([0639a8f](https://github.com/maidsafe/sn_node/commit/0639a8fb3a9749259968d05eb46f1c79a6eee190))
* simulated payout ([8293d03](https://github.com/maidsafe/sn_node/commit/8293d03beb2aea51be24d3462452dbcb0d410e7b))
* storecost ([b7f49ad](https://github.com/maidsafe/sn_node/commit/b7f49ad686dd0c68b1afacdf2e443ece3dd45c75))
* **accumulation:** accumulate elder to adult messages at destination ([12c2312](https://github.com/maidsafe/sn_node/commit/12c23122125f67eb7969366e7c49501677c562a8))
* **aggregation:** set AtDestination where needed, and use section src ([814bb78](https://github.com/maidsafe/sn_node/commit/814bb785e5a1da79bdf0db6ec877df9c1293acb6))
* **chunks:** handle read/write ([06b888d](https://github.com/maidsafe/sn_node/commit/06b888d1c2a303a1113d95d5176330f0d19bdc6b))
* **chunks:** set chunks at start, reset when levelup, set when level down ([797a17b](https://github.com/maidsafe/sn_node/commit/797a17bf99c1dd6743202496f94a8d301fd93c6d))
* **churn:** handle wallet churn msgs ([3413025](https://github.com/maidsafe/sn_node/commit/3413025e9a3f278ae48ddc022d9fa98121758bb4))
* **churn:** put newbies into churn mode as well ([0162036](https://github.com/maidsafe/sn_node/commit/0162036af5e4ceb472b59bcc2d857fa91aea47cb))
* **churning wallets:** simplify churn ([10485b8](https://github.com/maidsafe/sn_node/commit/10485b8b5bffe3835929e7d2422369396ef3f1ea))
* **data_cmd:** process payment for data command ([888337d](https://github.com/maidsafe/sn_node/commit/888337dad29d3a96a4a156709982be56759e4fc0))
* **funds_split:** use genesis flow for creating new wallet ([3810f29](https://github.com/maidsafe/sn_node/commit/3810f29270da05cc85f1bca692d0313af440ec02))
* **lazy:** keep msg context for domain logic errors ([18edbf7](https://github.com/maidsafe/sn_node/commit/18edbf7e341bdb405738f8e7ff5c85c34295df7e))
* **node:** handle promotion and demotion ([9a18633](https://github.com/maidsafe/sn_node/commit/9a186338b9b18d141bc4c80bcfb8c1ab67346c5a))
* **node:** init transfers and metadata after genesis ([815b0d0](https://github.com/maidsafe/sn_node/commit/815b0d0370e016571371f4d4dce6a3e52d719d90))
* **node_cmds:** enable mapping of node -> messages to process DataCmds ([3180519](https://github.com/maidsafe/sn_node/commit/31805191171c51998e90b2262be5fbd403805a15))
* **node_duties:** rename get wallet query ([e1fff62](https://github.com/maidsafe/sn_node/commit/e1fff62e37f6184c5f7c3a2c5ebcbb8f2219c4bd))
* **promotion:** allow Adult to receive Elder ops ([392f566](https://github.com/maidsafe/sn_node/commit/392f5664974844652553b3a5905c40e348b27c6c))
* **replication:** enable chunk replication on member left ([fad76e1](https://github.com/maidsafe/sn_node/commit/fad76e112e37604eedb7a8471398e9da532e6cd8))
* **rewards:** add reward payout mod ([d1e7e0f](https://github.com/maidsafe/sn_node/commit/d1e7e0f10ba42cc14cce558dcdac1227188bfdf2))
* **rewards:** enable reward payout again ([e8298da](https://github.com/maidsafe/sn_node/commit/e8298da568392a5ef621553ac456d9f3941fff36))
* chain payouts for section funds split ([f0e89c3](https://github.com/maidsafe/sn_node/commit/f0e89c3cc60f46a7be97f1cfe803f2de0cd6b5f8))
* create two transfers on split ([10cca6f](https://github.com/maidsafe/sn_node/commit/10cca6f5d891932894a89ec52ca22c69ecf6fca3))
* ElderPrep stage for adults ([0f3469e](https://github.com/maidsafe/sn_node/commit/0f3469e8ca63eda4d733f7f786986e814ea1d16e))
* start new elders straight away, dont wait for data to come in ([bc3b736](https://github.com/maidsafe/sn_node/commit/bc3b736204187bafbde9d97861b931d9f8925e20))


### Bug Fixes

* **data:** redirect data requests to the correct section if it does not ([5c3c195](https://github.com/maidsafe/sn_node/commit/5c3c195d60d2d2d302a4a1513a5f715324ca4128))
* post-rebase issues ([ce4f194](https://github.com/maidsafe/sn_node/commit/ce4f19451ed37622f2cafe9da012b0968b6ae8a6))
* remove some unnecessary logs ([7ef9542](https://github.com/maidsafe/sn_node/commit/7ef9542c819829752ec93ca1b5d0d144fe13e13d))
* **churn:** send prop and acc to our elders ([e0055c2](https://github.com/maidsafe/sn_node/commit/e0055c2d0b3497797257fbe894523b30aedc369b))
* **churn:** swarm wallet when created ([401d04d](https://github.com/maidsafe/sn_node/commit/401d04d8146d02eb666c27b0348b700ad38fff0f))
* add sibling key to constellation change ([d2551ac](https://github.com/maidsafe/sn_node/commit/d2551ac4566df4ff9d4b1e5b386d537d7133eedf))
* genesis elder count must be at least 5 ([7ff3703](https://github.com/maidsafe/sn_node/commit/7ff3703393f2e378d11881d6636af8e0238dca71))
* handle from_history error in transfers ([50c5c39](https://github.com/maidsafe/sn_node/commit/50c5c39e5692a298ad2394e2b12294344591d7da))
* handle nothing to sync error ([e20d437](https://github.com/maidsafe/sn_node/commit/e20d437912650d408863d76f33dcaab90a1b38cd))
* include remainder when splitting section funds ([f8094bb](https://github.com/maidsafe/sn_node/commit/f8094bb7975124c0138665a53cb55f2c843e300b))
* initiate elder change after becoming elder ([015fdf1](https://github.com/maidsafe/sn_node/commit/015fdf10bc8f5ddf32e08cc094f7a2d60ed008e9))
* pending transitions ([d30920a](https://github.com/maidsafe/sn_node/commit/d30920a0807e4a1555d51e64ff360a1f5a622fff))
* post-rebase issues ([ab40c41](https://github.com/maidsafe/sn_node/commit/ab40c41cad0385e36508cae829f4109451051240))
* pre aggregation commit changes ([5a3014f](https://github.com/maidsafe/sn_node/commit/5a3014f3feac4165ae4780994d82e14f71a812ed))
* process resulting duties ([13f9590](https://github.com/maidsafe/sn_node/commit/13f9590f06a9d64b4e6672e9aea35fa1847914ee))
* remove redundant origin field ([b341b00](https://github.com/maidsafe/sn_node/commit/b341b0002821cb1eb149b6b22e37f01083b0f768))
* ugly temp fix for lagging dkg outcome.. ([5673093](https://github.com/maidsafe/sn_node/commit/5673093cdd76388c8b608fa5e27bbd17b82500f4))
* wire up last stage of creating wallet ([4c01773](https://github.com/maidsafe/sn_node/commit/4c0177366c1b59eeac4f5b5e7bb67d1fe95e2773))
* **elder:** query old key when new ([9a48bc2](https://github.com/maidsafe/sn_node/commit/9a48bc2f4112c91eb9a0bba51a65be34deae8c5d))
* **genesis:** init full section funds at completed ([108265e](https://github.com/maidsafe/sn_node/commit/108265ec4b6c5859df3a7e40cc6869e501a5d841))
* **genesis:** proper check if genesis ([fee55b8](https://github.com/maidsafe/sn_node/commit/fee55b8a39d244dc3139cd34933057465779abe5))
* **genesis:** propose also when still elder ([b8c790c](https://github.com/maidsafe/sn_node/commit/b8c790c06e129b0c5367ed748566282dcbb8671b))
* **section_funds:** reset transition after completed ([eba03da](https://github.com/maidsafe/sn_node/commit/eba03da2ac4af5f5d6c7ce97f07df13d7f5292ff))
* **transition:** derive Clone for multiple structs ([335b93e](https://github.com/maidsafe/sn_node/commit/335b93e89156b53046963994030c34b513d0c86c))
* **transition:** start transition after getting Section Wallet history ([f49ed54](https://github.com/maidsafe/sn_node/commit/f49ed54233a70d848051f21eb9ce6c8f2bc25983))
* **walletstage:** actually add the signatures ([12cc467](https://github.com/maidsafe/sn_node/commit/12cc4673b0d77fb10db371a7fcba54a94f365460))
* send wallet history query to our section ([ca58521](https://github.com/maidsafe/sn_node/commit/ca58521e8b24514f58923af93b072292b90b8d4d))


* dep updates and changes for split ([10a291d](https://github.com/maidsafe/sn_node/commit/10a291d66856b914e6738d5e2e3d87374858ac82))
* **messaging:** add expected aggregation scheme, and use an itinerary ([6d3d970](https://github.com/maidsafe/sn_node/commit/6d3d97025332a522bc0e2b0b94945406a358d7e0))

## [0.30.0](https://github.com/maidsafe/sn_node/compare/v0.29.0...v0.30.0) (2021-03-11)


### ⚠ BREAKING CHANGES

* **tokio:** new Tokio v1 is not backward compatible with previous runtime versions < 1.

* **tokio:** upgrade tokio to v1.3.0 ([ffb74f9](https://github.com/maidsafe/sn_node/commit/ffb74f9976172d49b92b42f51c1eaef6129e391f))

## [0.29.0](https://github.com/maidsafe/sn_node/compare/v0.28.2...v0.29.0) (2021-03-10)


### ⚠ BREAKING CHANGES

* **routing:** Policy mutation operations are removed.

Co-authored-by: oetyng <oetyng@gmail.com>
* **Seq:** Policy mutation operations are removed.

### Features

* **Seq:** upgrading sn_data_types to v0.16.0 which makes the Policy of a Sequence data type immutable. ([1334b08](https://github.com/maidsafe/sn_node/commit/1334b0876e4dabea492d425180e8199227b4c5b3))


* **routing:** upgrading sn_routing to 0.48.1 ([8659be7](https://github.com/maidsafe/sn_node/commit/8659be7ca580b5a62a0e0bd4c5f701cf51e244da))

### [0.28.2](https://github.com/maidsafe/sn_node/compare/v0.28.1...v0.28.2) (2021-03-04)

### [0.28.1](https://github.com/maidsafe/sn_node/compare/v0.28.0...v0.28.1) (2021-03-03)

## [0.28.0](https://github.com/maidsafe/sn_node/compare/v0.27.2...v0.28.0) (2021-02-25)


### ⚠ BREAKING CHANGES

* **accumulation:** this changes uses a new version of sn_messaging with a
breaking change

### Features

* **accumulation:** accumulate elder to adult messages at destination ([a91e3d3](https://github.com/maidsafe/sn_node/commit/a91e3d3603330c21a46a61f0bd076c8e7fe9de37))

### [0.27.2](https://github.com/maidsafe/sn_node/compare/v0.27.1...v0.27.2) (2021-02-25)

### [0.27.1](https://github.com/maidsafe/sn_node/compare/v0.27.0...v0.27.1) (2021-02-24)

## [0.27.0](https://github.com/maidsafe/sn_node/compare/v0.26.16...v0.27.0) (2021-02-24)


### ⚠ BREAKING CHANGES

* **deps:** New bootstrap flows and modified messaging types.

### Bug Fixes

* **config_file:** remove remaining occurrences of clear and fresh ([124ed70](https://github.com/maidsafe/sn_node/commit/124ed70f98cab343455348eb894f64df356bfc5c))
* **msg_analysis:** try all match methods for a msg ([fcadb77](https://github.com/maidsafe/sn_node/commit/fcadb773d879200c313c224471e073436cbe3334))
* logic errors, logging ([5b205c4](https://github.com/maidsafe/sn_node/commit/5b205c46a906edb2d2229416ae1a33a1a66bd0cd))


* **deps:** update sn_routing, sn_messaging, sn_transfers ([2916764](https://github.com/maidsafe/sn_node/commit/291676482aa2f33b85732183438a13a6acec224a))

### [0.26.16](https://github.com/maidsafe/sn_node/compare/v0.26.15...v0.26.16) (2021-02-17)


### Bug Fixes

* **used_space:** set the local used_space to zero instead of clearing ([1594b86](https://github.com/maidsafe/sn_node/commit/1594b8624228249862a6d70089298b3d49d1859a))

### [0.26.15](https://github.com/maidsafe/sn_node/compare/v0.26.14...v0.26.15) (2021-02-16)

### [0.26.14](https://github.com/maidsafe/sn_node/compare/v0.26.13...v0.26.14) (2021-02-15)


### Bug Fixes

* adds used_space.reset() and reset() on age-up ([1267872](https://github.com/maidsafe/sn_node/commit/1267872c2e73fc9c440c612c14819850ca303df6))
* unifies used space across node ([942c7f8](https://github.com/maidsafe/sn_node/commit/942c7f80f7002d95a33d88dfbdb4b143d43442e8))

### [0.26.13](https://github.com/maidsafe/sn_node/compare/v0.26.12...v0.26.13) (2021-02-15)

### [0.26.12](https://github.com/maidsafe/sn_node/compare/v0.26.11...v0.26.12) (2021-02-15)

### [0.26.11](https://github.com/maidsafe/sn_node/compare/v0.26.10...v0.26.11) (2021-02-11)

### [0.26.10](https://github.com/maidsafe/sn_node/compare/v0.26.9...v0.26.10) (2021-02-11)

### [0.26.9](https://github.com/maidsafe/sn_node/compare/v0.26.8...v0.26.9) (2021-02-11)

### [0.26.8](https://github.com/maidsafe/sn_node/compare/v0.26.7...v0.26.8) (2021-02-08)

### [0.26.7](https://github.com/maidsafe/sn_node/compare/v0.26.6...v0.26.7) (2021-02-04)


### Features

* give Config public interface ([4b859d8](https://github.com/maidsafe/sn_node/commit/4b859d8449f6caf75dc544be0cd8652f3adf0ced))

### [0.26.6](https://github.com/maidsafe/sn_node/compare/v0.26.5...v0.26.6) (2021-02-04)


### Bug Fixes

* NoOp when elder change has occured for various stages ([5fd50e2](https://github.com/maidsafe/sn_node/commit/5fd50e2951398fb4b9b6b88e06d95219073a52a1))
* save received transfer propagation ([e72ba81](https://github.com/maidsafe/sn_node/commit/e72ba8177866c53bc31964cf7e834e77665c36d4))

### [0.26.5](https://github.com/maidsafe/sn_node/compare/v0.26.4...v0.26.5) (2021-02-04)

### [0.26.4](https://github.com/maidsafe/sn_node/compare/v0.26.3...v0.26.4) (2021-02-04)

### [0.26.3](https://github.com/maidsafe/sn_node/compare/v0.26.2...v0.26.3) (2021-02-04)

### [0.26.2](https://github.com/maidsafe/sn_node/compare/v0.26.1...v0.26.2) (2021-02-03)


### Bug Fixes

* **adult:** fix adults overwriting their blob chunkstore on churns ([f823ee8](https://github.com/maidsafe/sn_node/commit/f823ee85001a04a2d40054b79b98f0997f17b33e))

### [0.26.1](https://github.com/maidsafe/sn_node/compare/v0.26.0...v0.26.1) (2021-02-03)

## [0.26.0](https://github.com/maidsafe/sn_node/compare/v0.25.41...v0.26.0) (2021-02-01)


### ⚠ BREAKING CHANGES

* rename money to token

* rename money to token ([e3d699c](https://github.com/maidsafe/sn_node/commit/e3d699cce291f9172b79d698cc7edeb3845690ab))

### [0.25.41](https://github.com/maidsafe/sn_node/compare/v0.25.40...v0.25.41) (2021-02-01)


### Bug Fixes

* remove println ([62b1c07](https://github.com/maidsafe/sn_node/commit/62b1c070fa295211cd565b78454e9417e93e80f4))
* **deps:** use correct deps ([ca66a89](https://github.com/maidsafe/sn_node/commit/ca66a89ec42f431dad57c9f6086ccff8ca4d5af3))
* **test:** impl proper sig verification for test signing ([a7fd147](https://github.com/maidsafe/sn_node/commit/a7fd1479f33fe281625404a676c2a7ac285b2e6c))
* address and remove comments ([a5017c2](https://github.com/maidsafe/sn_node/commit/a5017c22c57a504404d472a1e578216bd2d344fa))

### [0.25.40](https://github.com/maidsafe/sn_node/compare/v0.25.39...v0.25.40) (2021-01-29)


### Features

* **elder_change:** add finish step ([ef17827](https://github.com/maidsafe/sn_node/commit/ef17827de2e120f9f66dd6c1dd76946bfa9626bf))
* **multisig-actor:** use transfer share logic ([1e437a4](https://github.com/maidsafe/sn_node/commit/1e437a45b8a45f546e193f24f2500677766a64a9))
* **section_funds:** use other section as replicas ([43e61b6](https://github.com/maidsafe/sn_node/commit/43e61b63e43598c4ac53254b888e81fdb1230235))
* **transfers:** impl multisig validation proposal ([56a9ef3](https://github.com/maidsafe/sn_node/commit/56a9ef386a11c35f78150f9f812377fa6ba03754))


### Bug Fixes

* check for is_section not is_elder in msg_analysis ([fc9841b](https://github.com/maidsafe/sn_node/commit/fc9841b39ce62fabceed1d64c191bb0203ba6753))
* **adult:** instantiate new adult state ([bd805f2](https://github.com/maidsafe/sn_node/commit/bd805f243e9e498ccd2a7bb951336a926f9f4ff2))
* **clippy:** remove conversion to same type ([237d791](https://github.com/maidsafe/sn_node/commit/237d791b6d70bfc6c3166fc64685e892fa7ebded))
* **genesis:** use sn_transfer genesis ([f14b376](https://github.com/maidsafe/sn_node/commit/f14b376beea6f3ea6c8ed4f04624f6d65c29ed95))
* **init:** process results at assuming duties ([e1a85d6](https://github.com/maidsafe/sn_node/commit/e1a85d603b8baac2c843245365b9c0537bde7811))
* **msganalysis:** expect validation from transfers ([a5f96fc](https://github.com/maidsafe/sn_node/commit/a5f96fc768e6366cc9ab51130c9cbaf41ea89981))
* **rewards:** return error when deactivation fails ([452a458](https://github.com/maidsafe/sn_node/commit/452a4582f8abd52193d1e515caa775f520a6786a))
* add node signing to adult and elder state ([bba2b96](https://github.com/maidsafe/sn_node/commit/bba2b96523d4e4f76a86c6a835baf2fc90657f2a))
* botched conversion ([f681c24](https://github.com/maidsafe/sn_node/commit/f681c2422ac1e9c9e27121383fb1d50499683384))
* clippy warnings ([3b667ef](https://github.com/maidsafe/sn_node/commit/3b667ef9e2ffe91d7c03d8af609e4e52d545ec52))
* enqueue elder ops while assuming elder duties ([88ed190](https://github.com/maidsafe/sn_node/commit/88ed19073620ce1882863f9323cccb0797ea84be))

### [0.25.39](https://github.com/maidsafe/sn_node/compare/v0.25.38...v0.25.39) (2021-01-28)

### [0.25.38](https://github.com/maidsafe/sn_node/compare/v0.25.37...v0.25.38) (2021-01-28)

### [0.25.37](https://github.com/maidsafe/sn_node/compare/v0.25.36...v0.25.37) (2021-01-27)


### Features

* **launch_tool:** pass RUST_LOG value to the launch_tool --rust-log arg ([662c827](https://github.com/maidsafe/sn_node/commit/662c827817c62b615c5ca68586b32e4278141a4b))

### [0.25.36](https://github.com/maidsafe/sn_node/compare/v0.25.35...v0.25.36) (2021-01-26)


### Features

* removal signature aggregate ([8bac521](https://github.com/maidsafe/sn_node/commit/8bac52163748bdc1fde54b3436c042fbd8f46b02))

### [0.25.35](https://github.com/maidsafe/sn_node/compare/v0.25.34...v0.25.35) (2021-01-25)

### [0.25.34](https://github.com/maidsafe/sn_node/compare/v0.25.33...v0.25.34) (2021-01-25)

### [0.25.33](https://github.com/maidsafe/sn_node/compare/v0.25.32...v0.25.33) (2021-01-25)

### [0.25.32](https://github.com/maidsafe/sn_node/compare/v0.25.31...v0.25.32) (2021-01-21)


### Bug Fixes

* **hack:** connection lag via lowering qp2p timeouts ([e6e1375](https://github.com/maidsafe/sn_node/commit/e6e137585f4f6726123a63d94ed981d35614f4c1))

### [0.25.31](https://github.com/maidsafe/sn_node/compare/v0.25.30...v0.25.31) (2021-01-20)

### [0.25.30](https://github.com/maidsafe/sn_node/compare/v0.25.29...v0.25.30) (2021-01-19)

### [0.25.29](https://github.com/maidsafe/sn_node/compare/v0.25.28...v0.25.29) (2021-01-18)

### [0.25.28](https://github.com/maidsafe/sn_node/compare/v0.25.27...v0.25.28) (2021-01-18)

### [0.25.27](https://github.com/maidsafe/sn_node/compare/v0.25.26...v0.25.27) (2021-01-17)


### Bug Fixes

* dont use bincode for envelope deserialization ([818f75b](https://github.com/maidsafe/sn_node/commit/818f75b3a405d9b80e403d8d9f21e6e2803b332b))

### [0.25.26](https://github.com/maidsafe/sn_node/compare/v0.25.25...v0.25.26) (2021-01-15)


### Features

* **errors:** more mapping to sn_messages ([22fdd7d](https://github.com/maidsafe/sn_node/commit/22fdd7dcdb523178b422d5d12627b98b1cc592f2))

### [0.25.25](https://github.com/maidsafe/sn_node/compare/v0.25.24...v0.25.25) (2021-01-14)

### [0.25.24](https://github.com/maidsafe/sn_node/compare/v0.25.23...v0.25.24) (2021-01-14)

### [0.25.23](https://github.com/maidsafe/sn_node/compare/v0.25.22...v0.25.23) (2021-01-14)

### [0.25.22](https://github.com/maidsafe/sn_node/compare/v0.25.21...v0.25.22) (2021-01-14)

### [0.25.22](https://github.com/maidsafe/sn_node/compare/v0.25.21...v0.25.22) (2021-01-14)

### [0.25.22](https://github.com/maidsafe/sn_node/compare/v0.25.21...v0.25.22) (2021-01-14)

### [0.25.21](https://github.com/maidsafe/sn_node/compare/v0.25.20...v0.25.21) (2021-01-14)

### [0.25.21](https://github.com/maidsafe/sn_node/compare/v0.25.20...v0.25.21) (2021-01-14)

### [0.25.20](https://github.com/maidsafe/sn_node/compare/v0.25.19...v0.25.20) (2021-01-14)

### [0.25.20](https://github.com/maidsafe/sn_node/compare/v0.25.19...v0.25.20) (2021-01-14)

### [0.25.19](https://github.com/maidsafe/sn_node/compare/v0.25.18...v0.25.19) (2021-01-14)


### Features

* **errors:** add new more specific errors for invalid messages ([38a801a](https://github.com/maidsafe/sn_node/commit/38a801a57004b65305f01e6de7fb16131c9184a7))
* remove bootstrap stream listening also ([74855e2](https://github.com/maidsafe/sn_node/commit/74855e2bc2b1b14631c5921f52a40c3c16ea1dd6))
* remove stream storage for client management ([3313cd5](https://github.com/maidsafe/sn_node/commit/3313cd51d67541d8011b2295569d0cf1489a9128))
* **deps:** use updated client ([468b690](https://github.com/maidsafe/sn_node/commit/468b6901f5b4c3c8ceaca3c0b7bf9f7f79f45e0d))
* **errors:** use thiserror for error construction ([946e3c2](https://github.com/maidsafe/sn_node/commit/946e3c2e38d88afd3082a9d345db1fbef155359b))
* remove client challenge ([50e3ed4](https://github.com/maidsafe/sn_node/commit/50e3ed45802c09ada8af2f1b8b2315e4e20319e7))
* **config:** add support for --clean and --fresh flags ([0c29503](https://github.com/maidsafe/sn_node/commit/0c2950305eafeddc9f193e49bd246028f56dfb57))
* **errors:** use thiserror for error construction ([678384e](https://github.com/maidsafe/sn_node/commit/678384e741822c1fa29b8cb1e6b48be160235316))


### Bug Fixes

* **rate_limit tests:** use u64 instead of f64.. ([56db5ab](https://github.com/maidsafe/sn_node/commit/56db5abbeedcf5bd0820bd2a18e5810f51c05225))

### [0.25.19](https://github.com/maidsafe/sn_node/compare/v0.25.18...v0.25.19) (2021-01-14)


### Features

* **errors:** add new more specific errors for invalid messages ([38a801a](https://github.com/maidsafe/sn_node/commit/38a801a57004b65305f01e6de7fb16131c9184a7))
* remove bootstrap stream listening also ([74855e2](https://github.com/maidsafe/sn_node/commit/74855e2bc2b1b14631c5921f52a40c3c16ea1dd6))
* remove stream storage for client management ([3313cd5](https://github.com/maidsafe/sn_node/commit/3313cd51d67541d8011b2295569d0cf1489a9128))
* **deps:** use updated client ([468b690](https://github.com/maidsafe/sn_node/commit/468b6901f5b4c3c8ceaca3c0b7bf9f7f79f45e0d))
* **errors:** use thiserror for error construction ([946e3c2](https://github.com/maidsafe/sn_node/commit/946e3c2e38d88afd3082a9d345db1fbef155359b))
* remove client challenge ([50e3ed4](https://github.com/maidsafe/sn_node/commit/50e3ed45802c09ada8af2f1b8b2315e4e20319e7))
* **config:** add support for --clean and --fresh flags ([0c29503](https://github.com/maidsafe/sn_node/commit/0c2950305eafeddc9f193e49bd246028f56dfb57))
* **errors:** use thiserror for error construction ([678384e](https://github.com/maidsafe/sn_node/commit/678384e741822c1fa29b8cb1e6b48be160235316))


### Bug Fixes

* **rate_limit tests:** use u64 instead of f64.. ([56db5ab](https://github.com/maidsafe/sn_node/commit/56db5abbeedcf5bd0820bd2a18e5810f51c05225))

### [0.25.18](https://github.com/maidsafe/sn_node/compare/v0.25.17...v0.25.18) (2020-12-21)

### [0.25.17](https://github.com/maidsafe/sn_node/compare/v0.25.16...v0.25.17) (2020-12-21)


### Bug Fixes

* return Balance(0) when no db found ([99f7308](https://github.com/maidsafe/sn_node/commit/99f73087777498bbae3b2522e5f2c0cf993589d3))

### [0.25.16](https://github.com/maidsafe/sn_node/compare/v0.25.15...v0.25.16) (2020-12-21)

### [0.25.15](https://github.com/maidsafe/sn_node/compare/v0.25.14...v0.25.15) (2020-12-17)


### Bug Fixes

* disregard startup_relocation ([5117e30](https://github.com/maidsafe/sn_node/commit/5117e30b0b1b3d7dc2efdb0ce676559176a66728))

### [0.25.14](https://github.com/maidsafe/sn_node/compare/v0.25.13...v0.25.14) (2020-12-17)


### Bug Fixes

* db format ([c79bda5](https://github.com/maidsafe/sn_node/commit/c79bda5fb68db5553c1110be71a6da6d19fd9876))

### [0.25.13](https://github.com/maidsafe/sn_node/compare/v0.25.12...v0.25.13) (2020-12-17)


### Features

* **section_funds:** initiate section actor WIP ([e093675](https://github.com/maidsafe/sn_node/commit/e09367560975f0197e919454e97186338cfa0457))
* **storage:** impl adult storage tracking at Elders ([11215bd](https://github.com/maidsafe/sn_node/commit/11215bd241bd653b9cc739202c63d164be943e2b))
* **storage:** monitor section storage and flip joins_allowed accordingly ([24ff1ce](https://github.com/maidsafe/sn_node/commit/24ff1ce94346cd04213b5c1bd510a0e408d3ee50))


### Bug Fixes

* **all:** remove unused dependency and fix clippy issues ([4ed5a73](https://github.com/maidsafe/sn_node/commit/4ed5a73e3e43a2be96f0d12b58ec86d2094385fb))
* **blob:** fix blob msg accumulation ([4becc9d](https://github.com/maidsafe/sn_node/commit/4becc9defc54dbadabe8c297d61811e9a795bf9f))
* **blob:** fix verification of blob replication messages ([201f9e8](https://github.com/maidsafe/sn_node/commit/201f9e8046c0eefed14d974987bd8a2acd2a1d71))
* **blob:** short circuit blob query messaging ([4b39dc8](https://github.com/maidsafe/sn_node/commit/4b39dc87aafcb8172366303f29e6b5db66fd9161))
* **messagning:** fix msg wrapping at adults and elders ([0aa3b70](https://github.com/maidsafe/sn_node/commit/0aa3b708c9ae10f320bf2e86cebb5b14fca9b655))
* **msg_analysis:** accumulate node queries + resp ([9fc4363](https://github.com/maidsafe/sn_node/commit/9fc436365ceaa1f9d9c09e388d0d2fcca314d0ee))
* **msg_analysis:** remove incorrect accumulation ([e270455](https://github.com/maidsafe/sn_node/commit/e270455083894d3a5ab1cf3ff6453ebd03a47dcf))
* **sn_node:** set sn_node thread stack size ([9a42cd9](https://github.com/maidsafe/sn_node/commit/9a42cd9e829551a643e93a0616e03a2913b23db4))
* **storage:** fix storage calculation and improve logging ([77fb9f6](https://github.com/maidsafe/sn_node/commit/77fb9f667a10b3b092897a2cee142ceb96675fe4))
* **storage:** increase default maximum capacity ([8dfc35c](https://github.com/maidsafe/sn_node/commit/8dfc35c0c385b489b9482f46103b6c89347f2fd0))
* compile + clippy errors ([d6a51a4](https://github.com/maidsafe/sn_node/commit/d6a51a44a157f256837e21db2fb2d21f87124194))
* do not accumulate node query ([7b3c0f0](https://github.com/maidsafe/sn_node/commit/7b3c0f0529a26aac5d3801d35ca381da9b6f1a15))
* don't apply transfers to store if already seen. ([9f895ad](https://github.com/maidsafe/sn_node/commit/9f895ad22b9996844cde9e7552033812f45aec37))
* Ensure to store TransferStore in lock ([5172011](https://github.com/maidsafe/sn_node/commit/51720117ac7723dd1354141f87218c439c1a8828))
* hex encode serialised key ([8bbc235](https://github.com/maidsafe/sn_node/commit/8bbc2352c46abd80ea4e047ab878ffa9fcd6806b))
* re-add disabled match branch ([4fe82ec](https://github.com/maidsafe/sn_node/commit/4fe82ec8f6edf01292e81e4c8feb5c97fc00f2d9))
* return empty vec when key's transfer db doesn't exist ([05fb09e](https://github.com/maidsafe/sn_node/commit/05fb09e85f89ad9cb5462b022d7f0e4d56b2a6f6))
* **tests:** make tests compile and run ([c8b6037](https://github.com/maidsafe/sn_node/commit/c8b60370e3b03b152f85bd6847e3093be1633057))
* **transfers:** fix genesis, sigs and store keys ([194a9a3](https://github.com/maidsafe/sn_node/commit/194a9a317b0ed0880ba74f136a3e3898db7a949c))
* reimplement overwritten hex encode fix ([aa50061](https://github.com/maidsafe/sn_node/commit/aa50061efe35d2069a9ac4612513dd7d23a56a96))
* **wallet:** lock over the db on write ([a6f5127](https://github.com/maidsafe/sn_node/commit/a6f5127f0130c56fdac4ce0429ff3ebedbae5995))

### [0.25.12](https://github.com/maidsafe/sn_node/compare/v0.25.11...v0.25.12) (2020-12-16)


### Features

* more logs ([14cc036](https://github.com/maidsafe/sn_node/commit/14cc0366dbb5ea1ba7bb04b7fa315986c933ccbc))

### [0.25.11](https://github.com/maidsafe/sn_node/compare/v0.25.10...v0.25.11) (2020-12-15)


### Bug Fixes

* config init ([2348a8d](https://github.com/maidsafe/sn_node/commit/2348a8dd64b8a07be0db2a3e66b0c728e1a6e082))
* **sn_node:** set sn_node thread stack size ([435b50b](https://github.com/maidsafe/sn_node/commit/435b50bfd64526484d0f9d0e56d3263fa0266991))

### [0.25.10](https://github.com/maidsafe/sn_node/compare/v0.25.9...v0.25.10) (2020-12-15)

### [0.25.9](https://github.com/maidsafe/sn_node/compare/v0.25.8...v0.25.9) (2020-12-08)


### Features

* **adult:** enable chunk duplication at adults ([771c618](https://github.com/maidsafe/sn_node/commit/771c618d9e35fccb2cafb2362eb4929ee63d04f5))


### Bug Fixes

* **blob:** verify unpub blob owner ([0a4b5c7](https://github.com/maidsafe/sn_node/commit/0a4b5c748260b465015dd28c69901eca187cfaf1))
* **duplication:** fix message parsing for chunk duplication at adults ([5ea395f](https://github.com/maidsafe/sn_node/commit/5ea395ff1b63e8f08be92e76f84f355117f37d45))

### [0.25.8](https://github.com/maidsafe/sn_node/compare/v0.25.7...v0.25.8) (2020-12-08)


### Features

* update data types and client deps ([55249e1](https://github.com/maidsafe/sn_node/commit/55249e1db0c06334fa583e1370a40cd72d3da045))

### [0.25.7](https://github.com/maidsafe/sn_node/compare/v0.25.6...v0.25.7) (2020-12-07)


### Bug Fixes

* **blob:** rebase atop latest master ([74a88dc](https://github.com/maidsafe/sn_node/commit/74a88dc513d8fb4a0c1f90f493e30fa9c89f9d61))
* **blob:** verify unpub blob owner ([36318be](https://github.com/maidsafe/sn_node/commit/36318be0b6e53e63cd98a7cf2fc59401563aac2d))
* **data:** verify owner before writing/deleting new data ([88addf9](https://github.com/maidsafe/sn_node/commit/88addf9e70888afaf937c8a06e17d548b500a06e))

### [0.25.6](https://github.com/maidsafe/sn_node/compare/v0.25.5...v0.25.6) (2020-12-03)

### [0.25.5](https://github.com/maidsafe/sn_node/compare/v0.25.4...v0.25.5) (2020-12-02)

### [0.25.4](https://github.com/maidsafe/sn_node/compare/v0.25.3...v0.25.4) (2020-12-01)

### [0.25.3](https://github.com/maidsafe/sn_node/compare/v0.25.2...v0.25.3) (2020-12-01)

### [0.25.2](https://github.com/maidsafe/sn_node/compare/v0.25.1...v0.25.2) (2020-12-01)


### Features

* **async:** adapt tests and fix typo-induced bug ([cbcb44d](https://github.com/maidsafe/sn_node/commit/cbcb44dcbf7537608f9054a256bbce232cdbec40))
* **async:** adds used_space max_capacity() getter ([7ca06eb](https://github.com/maidsafe/sn_node/commit/7ca06eb4c12aee2ddc4655d559ce6d72a942025f))
* **async:** introduce async logging and make functions async/await to ([1b18a95](https://github.com/maidsafe/sn_node/commit/1b18a956bb769f517eb442744326e5fcd2c6faae))
* **async:** load keys/age concurrently on startup ([a48d6a4](https://github.com/maidsafe/sn_node/commit/a48d6a441eda274e7e365714e87715d40ce8a900))
* **async:** made used space tracking async-safe ([1c7a621](https://github.com/maidsafe/sn_node/commit/1c7a6210d747dd0b56677dc001119f2560fecca4))
* **async-log:** re-introduce async logging using a wrapper ([337ac57](https://github.com/maidsafe/sn_node/commit/337ac5715dc85d20ac16b8c14d7ed084a70f1b63))
* **chunkduplication:** enable duplication trigger ([48799c2](https://github.com/maidsafe/sn_node/commit/48799c244a1fd7d4ac7efbe48c58d33bf9f5c38b))
* **duty_cfg:** cover first node, adult and elder ([2c17416](https://github.com/maidsafe/sn_node/commit/2c17416bda0e181cf59805c32cb9b8b7951734c7))
* **elder:** set bls keys on promoted ([4233ec6](https://github.com/maidsafe/sn_node/commit/4233ec6bdea8f54f109202113f33a7fbb8774d54))
* **farming:** accumulate reward on data write ([16310b3](https://github.com/maidsafe/sn_node/commit/16310b313198286a57de7382428d95a466b7a822))
* **farming:** add some temp calcs of base cost ([e250759](https://github.com/maidsafe/sn_node/commit/e250759035a61337c845f4a0a37d95d4ca448906))
* **farming:** new section account on elder churn ([062cab6](https://github.com/maidsafe/sn_node/commit/062cab6d9bd32ddd215fd10f728894e4c9ea2509))
* **farming:** update metrics on elder churn ([7d9c55c](https://github.com/maidsafe/sn_node/commit/7d9c55c52dface58b9512efd59ac387b41b2f6f9))
* **genesis:** first node introduces all money ([3068865](https://github.com/maidsafe/sn_node/commit/3068865a7368d61402bd192313f4917f10db0373))
* **launch:** network launcher will build current sn_node before launch ([2c1c56a](https://github.com/maidsafe/sn_node/commit/2c1c56a32bce11d8206cde4e2c5770e0ce6ff9b4))
* **launch:** network launcher will build current sn_node before launch ([6f5c49d](https://github.com/maidsafe/sn_node/commit/6f5c49d368f65e938c02506be5d118c58e7ed9c4))
* **metadata:** set and delete chunk holders ([d4817b5](https://github.com/maidsafe/sn_node/commit/d4817b542a811460c8dfac659707d1e2ac58dc17))
* **msganalysis:** add detection of node transfers ([99b12c2](https://github.com/maidsafe/sn_node/commit/99b12c27f3a4f52d283f1a0f235ed298e238807f))
* **node_wallet:** separate node id and wallet key ([18868ea](https://github.com/maidsafe/sn_node/commit/18868ea12ab517a89bb4d29c9b49f875784e7ae9))
* **payment:** add query for store cost ([6071931](https://github.com/maidsafe/sn_node/commit/60719318b4143f431d2d5fb4b90530d427450ca6))
* **replica:** complete the init query flow ([92a9a4b](https://github.com/maidsafe/sn_node/commit/92a9a4b9444c9aae6ef65d0daa1aa82dd867b5f1))
* **section_actor:** enable naive transition ([61e5954](https://github.com/maidsafe/sn_node/commit/61e595416127371d827efc26153d741156b7e25f))
* **section_funds:** set new actor on elder churn ([ff41cf4](https://github.com/maidsafe/sn_node/commit/ff41cf4fed16a177005a68a88d4bd5fd5571df78))
* **seq:** update for latest seq data_type changes ([34dfb17](https://github.com/maidsafe/sn_node/commit/34dfb17b4a96e844be1a9ac792ef41aa002c4896))
* **transfers:** impl StoreCost for data writes ([70f93c7](https://github.com/maidsafe/sn_node/commit/70f93c72adc307df35bb58820f9f8efa20c9b877))
* add testnet launcher bin, using snlt ([90710ea](https://github.com/maidsafe/sn_node/commit/90710ea74638f9f47df483803d32579121f5f978))
* **chaos:** add chaos macro to randomly perform chaos ([cfbf3a0](https://github.com/maidsafe/sn_node/commit/cfbf3a01bafc2edf02e85e71e63c81b0c5c73011))
* **logs:** create separate log files for each thread ([d0dd77a](https://github.com/maidsafe/sn_node/commit/d0dd77a7f76813f87698578c848a6452f84bde56))
* **node wallet:** simplify pubkey to/from config ([505de20](https://github.com/maidsafe/sn_node/commit/505de2060567ce11da5f21e2bbe2d4fd379d0506))
* **rewards:** accumulate reward counter ([96936e6](https://github.com/maidsafe/sn_node/commit/96936e64074420c94550d88aff7fc79b7f8dbf44))
* **rewards:** payout rewards to elders on split ([44bc3ea](https://github.com/maidsafe/sn_node/commit/44bc3ea753bcf1b1c438d0110d97fe935327198b))
* **rewards:** rewards declining with network size ([2060107](https://github.com/maidsafe/sn_node/commit/20601071e7bf2e3d9cd7f1dadcc57c6069a0448f))
* **rewards:** set node reward wallet at startup ([b062fda](https://github.com/maidsafe/sn_node/commit/b062fda7dbcba0d4e9bc6d34f87d36535c2e4ac3))
* **rewards:** use msg_id for idempotency ([04220f4](https://github.com/maidsafe/sn_node/commit/04220f459e4d1d98d0d2b8b3498755bac6ad1ba6))
* **transfers:** keep key subset at replicas ([0943f06](https://github.com/maidsafe/sn_node/commit/0943f066098b3760e1224421bde48452bd657e50))
* **transfers:** store transfers to disk ([82d65cf](https://github.com/maidsafe/sn_node/commit/82d65cf5e0db43f4409ab8d261113f2860202937))
* **writes:** use dynamic rate limit for writes ([0b86894](https://github.com/maidsafe/sn_node/commit/0b868948234ad5809d3aa3271bc2d75e1b0cacc5))
* add `phase-one` feature for updates ([7a1c1ca](https://github.com/maidsafe/sn_node/commit/7a1c1ca0f0b9b1a647513579af85b164606fe66d))
* complete farming flow ([e9db602](https://github.com/maidsafe/sn_node/commit/e9db60298a3a09a7875bb5018003369b03ad08e0))


### Bug Fixes

* **ci:** fix coveralls failure in CI ([c92a6cc](https://github.com/maidsafe/sn_node/commit/c92a6cc58ef8fe5eeda044b2723a78172888f5a9))
* **tests:** config obj expected size ([c44c137](https://github.com/maidsafe/sn_node/commit/c44c137cebb81818dfa16a5e110f44561df40b31))
* **tests:** remove unnecessary assertion on size ([26b21ad](https://github.com/maidsafe/sn_node/commit/26b21ad9893cc4b45407726f471a7c22e2a44102))
* clippy warnings ([24145f5](https://github.com/maidsafe/sn_node/commit/24145f5cf28616b4ca1f38604b614ed7c17e368f))
* temp convert name + top lvl err handle method ([8b415c7](https://github.com/maidsafe/sn_node/commit/8b415c78bf4d9a30a979b36a062ff27b45aa596c))
* **build:** fix conflicts after rebase, remove deprecated API use ([d7ae205](https://github.com/maidsafe/sn_node/commit/d7ae20597666be98a90cef253e721dbff5661df4))
* **client response:** add missing await for message matching ([7019fa6](https://github.com/maidsafe/sn_node/commit/7019fa6ebea8447b4c1dd4ff82f2fd9ce1bd0e83))
* **clippy:** Clippy enum fixes ([0554b4f](https://github.com/maidsafe/sn_node/commit/0554b4f8b86867a2e41fdf02b2b2452b4d8d1149))
* **clippy:** fix last clippy warnings ([83b64ab](https://github.com/maidsafe/sn_node/commit/83b64ab4dfe52951f402d64d4dc7cd5e107bc618))
* **clippy:** fix warnings after clippy update ([f2e25c2](https://github.com/maidsafe/sn_node/commit/f2e25c2c746b0bd1073f662cc7c4492af9a8f9b1))
* **clippy:** some clippy fixes (not all) ([4d0cba1](https://github.com/maidsafe/sn_node/commit/4d0cba1d03be051cd7c2a9bda34202846ffc1543))
* **clippy:** some refactors in tests to make clippy happy ([1bc59ca](https://github.com/maidsafe/sn_node/commit/1bc59caa038736d26cd22ee8eba2018ecdeaa8b2))
* **comms:** add flag to communicate with a Section as a Node ([d648ad3](https://github.com/maidsafe/sn_node/commit/d648ad3b712e88da6de00b10f3ed24412c62bd4e))
* **config:** put correct wallet test value ([16ef078](https://github.com/maidsafe/sn_node/commit/16ef078cef0fa387ef3730400de7d720da1bc40c))
* **config:** reenable writing to disk ([79f59b5](https://github.com/maidsafe/sn_node/commit/79f59b503c90c5d5414b8a7271cf75d39ab9bd85))
* **dependencies:** update bls_signature_aggregator ([6688efd](https://github.com/maidsafe/sn_node/commit/6688efd922b4c81d101dbbf53993678bf92b6e46))
* **dependencies:** update temp dependency switch ([bc18408](https://github.com/maidsafe/sn_node/commit/bc18408f1668dd1d3673ca9831a3ed1ea651cdd7))
* **dirs:** replace dirs_next with directories to set project paths ([d636426](https://github.com/maidsafe/sn_node/commit/d636426927c7f20e726abf14ee7bbdfb41292ab4))
* **docs:** update docs to reflect recent changes ([ae5c63a](https://github.com/maidsafe/sn_node/commit/ae5c63ac59b9c92c766cd3e429829da01fb1dad6))
* **docs:** Update duty config docs. ([40c4765](https://github.com/maidsafe/sn_node/commit/40c47652b74b9de6a8619f7dee37b849768644e2))
* **events:** fix adult promotion process ([015a013](https://github.com/maidsafe/sn_node/commit/015a0134e534c44336fdb57e704ddbadf0cb596c))
* **from_db_key:** missing option wrap ([fc489f5](https://github.com/maidsafe/sn_node/commit/fc489f5e7d8f80293cff82b1ac2408407fd6a794))
* **gateway:** add missing client event processing ([7ab3b17](https://github.com/maidsafe/sn_node/commit/7ab3b175739d8bb0db9bf85f204f95973ebfb226))
* **gateway:** process transfer msgs ([21dad58](https://github.com/maidsafe/sn_node/commit/21dad58a0b32119d333c4e40277139c18cb4cdd1))
* **gateway:** votefor process locally, not forward ([2016df6](https://github.com/maidsafe/sn_node/commit/2016df6f2538ce5b271db7dbf415f65ed47ba32b))
* **genesis:** pass in "ghost" source key ([1f582ea](https://github.com/maidsafe/sn_node/commit/1f582eaf8b27f405fba25480a90d444e8114341f))
* **minting:** velocity < 1 at < 50% supply ([e507ce5](https://github.com/maidsafe/sn_node/commit/e507ce58a655ef13246cb1de291645245f52eb46))
* **minting_velocity:** don't stop at 50% minted ([578c431](https://github.com/maidsafe/sn_node/commit/578c43166b4fc01ab094121e6b11f2c0a70d6176))
* **msg_analysis:** various bugs ([aabaeec](https://github.com/maidsafe/sn_node/commit/aabaeec2c0e6d772497a8419953f94c0e7575f56))
* **msg_sending:** use correct ids and addresses ([858722a](https://github.com/maidsafe/sn_node/commit/858722a74eb1ea0de328cfcc5b60adddf8dc0c6c))
* **msganalysis:** correctly identify msg to client ([f111567](https://github.com/maidsafe/sn_node/commit/f111567ecac260d2763984135903efbac0b8d50b))
* **msgs:** updates to use qp2p streams ([814668b](https://github.com/maidsafe/sn_node/commit/814668b0d1102b410d15b33eae51303f2fdbbdd2))
* **node:** create vault's root directory before writing to it ([513cfc1](https://github.com/maidsafe/sn_node/commit/513cfc1bead7c50c28579ec40ba046dc59347d3c))
* **node:** use node keypairs generated locally WIP ([4c520b5](https://github.com/maidsafe/sn_node/commit/4c520b56ffee9213224275a0ccd7abff3c1e2c0f))
* **node_ops:** add none to break infinite loop ([2dcc7f1](https://github.com/maidsafe/sn_node/commit/2dcc7f15e279cfe1095b0f61db433a92e3ca4dfd))
* **nodeduties:** set index of bls share ([8b85082](https://github.com/maidsafe/sn_node/commit/8b85082ec730eea676ac1ccc1809f03d5be3fb09))
* **onbarding:** only check clients w contains qry ([045d3dd](https://github.com/maidsafe/sn_node/commit/045d3ddae7453a62583fa89552cb41706ff419b1))
* **onboarding:** check if already accepted on ([eae22b3](https://github.com/maidsafe/sn_node/commit/eae22b384ea5135ec1d4a2f88a22ed8dbc80c088))
* **onboarding:** faulty elder address retreival ([eb38b78](https://github.com/maidsafe/sn_node/commit/eb38b7804d5fba057c5a88dbe215c48ab1258d0b))
* **onboarding:** idempotency check of bootstrap ([48c561a](https://github.com/maidsafe/sn_node/commit/48c561a1112a00b073d9c9b91582d49d156f0b4a))
* **onboarding:** return same challenge on repeated ([bf33bff](https://github.com/maidsafe/sn_node/commit/bf33bff27fd7d28f4ab777998c518bd70f090711))
* **process_while_any:** don't drop any from `ops` ([a992f5f](https://github.com/maidsafe/sn_node/commit/a992f5f078bbb41e5b6e9651a3f20c73d8b51897))
* **promotion:** update to latest routing and fix promoting node to adult ([5528b09](https://github.com/maidsafe/sn_node/commit/5528b098751391a540bc7673c5c5c0687ca4b43e))
* **proxy_handling:** fix proxy_handling for section-to-section messaging ([1543014](https://github.com/maidsafe/sn_node/commit/154301424427bb430680abbb9bc5a720138d667b))
* **rate_limit:** query network for all adults ([f428f17](https://github.com/maidsafe/sn_node/commit/f428f175ed33f87f88f90d9a382ba9aeb81e27e4))
* **replica_init:** clear init flag also when first ([d1765ca](https://github.com/maidsafe/sn_node/commit/d1765cabad62f0baf8528c88c85d338b28b13073))
* **replica_init:** have genesis node init replica ([cb61ef3](https://github.com/maidsafe/sn_node/commit/cb61ef35695f74f8fea909a974c55986150ec349))
* **reward_cfg:** register on connected to network ([a1e976f](https://github.com/maidsafe/sn_node/commit/a1e976f7f16c4173844e2e36803bbe98403ef06a))
* **routing:** remove unused is_genesis func ([6407959](https://github.com/maidsafe/sn_node/commit/6407959f80f1abc8aad98b524d86981cec3312c3))
* **storecost:** div section balan by allnodes sqrd ([74814d3](https://github.com/maidsafe/sn_node/commit/74814d3f87f2ed7606e2cf2bc8b44fd93d45c009))
* **test:** final fixes for test suite ([2ab562b](https://github.com/maidsafe/sn_node/commit/2ab562b6730193d96bfa45925d20c852757e8e4e))
* **test:** update name and assert correct value ([d929c8f](https://github.com/maidsafe/sn_node/commit/d929c8fc3d7286bf62933ba52175edc157094f6b))
* **tests:** add missing calls to start_network ([57751bd](https://github.com/maidsafe/sn_node/commit/57751bdb43f7ec51c144cf453bf14580d415e248))
* **tests:** add RUST_FLAGS -D to test scripts ([83e12e4](https://github.com/maidsafe/sn_node/commit/83e12e4a857be7c48a1d12d71a59b7ad2ea5c21a))
* **tests:** update references to scl ([1efc59b](https://github.com/maidsafe/sn_node/commit/1efc59be105a0fc8097b34df9b94502c6263cf43))
* **transfer store:** Check for lists existence. ([618d33d](https://github.com/maidsafe/sn_node/commit/618d33d6ec69186ede6626b1f3c2ba140fbd8add))
* **transfers:** fix sending dst on registering a transfers ([1fccf16](https://github.com/maidsafe/sn_node/commit/1fccf160942b02621642013003e1f62d566fa596))
* **transfers:** get history requests now return history. ([7590bd0](https://github.com/maidsafe/sn_node/commit/7590bd0ef746f74af60a92859be1cd06c5e8457b))
* **transfers:** send to client ([c1f5b52](https://github.com/maidsafe/sn_node/commit/c1f5b524de7e4ae825984c1f620caee1be7eb6df))
* **transfers:** xpect client as most recent sender ([61593e4](https://github.com/maidsafe/sn_node/commit/61593e4b0cc43972571deb742f39211f5dca7ce3))
* add visibility modifiers ([4d335a8](https://github.com/maidsafe/sn_node/commit/4d335a8dcf2cf8ac02be52ec3f08e0872849694a))
* disable one missing validation of duplication ([2ecc390](https://github.com/maidsafe/sn_node/commit/2ecc3903f617fbaad9fd351442e7f78521463ebb))
* pre-reserve space in case of write fail ([f040acd](https://github.com/maidsafe/sn_node/commit/f040acdd3ee6269fe223bc7b7c808a6e4de1181c))
* remove non-existing field ([aeee3b8](https://github.com/maidsafe/sn_node/commit/aeee3b82f9cde660f62d1cd2ac914f1fd407f503))

### [0.25.1](https://github.com/maidsafe/sn_node/compare/v0.25.0...v0.25.1) (2020-07-16)
* fix/idata: make PUT request processing faster

### [0.25.0](https://github.com/maidsafe/sn_node/compare/0.24.0...v0.25.0) (2020-07-16)
* feat/data: support for Sequence data type and associated requests.
* feat/sequence: support for CRDT mutations on Sequence permissions and owner.
* test/sequence: add integration test for Sequence operations.
* feat/accumulator: collect BLS signatures in the vault to validate requests.
* fix/duplication: fix bugs in duplication mechanism and clippy fixes.
* fix/duplicaton: add the duplicated data to the holder list correctly.
* test/integration: ignore put_immutable_data test.
* fix/duplication: fix signature accumulation for duplication.
* fix/log: Fix misleading vault message.
* fix/idata: wait for all holders to process mutation requests.

### [0.24.0] (2020-06-11)
* When a Node starts, start it as an Adult. Create the additional modules required only when it is promoted to an Elder.
* Give Adults the responsibility of holding Immutable Data chunks.
* Use routing's messaging API with signature accumulation for intra-section communication.
* Implement chunk duplication if a node leaves the network. This will maintain the minimum number of copies required.
* Update to the latest version of `quic-p2p` which enables automatic port forwarding using the IGD protocol.
* Gracefully end the node process on SIGINT.
* Use the latest version of `routing`.
* Update to safe-nd 0.9.0 with refactored `Request` and `Response` enums.
* Separate the Client Handler into smaller sub-modules.

### [0.23.0]
* Enable required features in self-update dependency to support untar and unzip for packages
* Add tarpaulin to GHA and push result to coveralls
* Update to latest routing

### [0.22.0]
* Support a --update-only flag which only attempts to self-update binary
* Update readme to link to contributing guidelines doc
* Don't send client requests to PARSEC
* Add dead_code on vote_for_action
* Fix spacing bug for clippy

### [0.21.0]
* improve app authorisation
* introduce ParsecAction
* complete indirection between vote and consensus
* replace other payed action but login
* add basic mock routing functions
* send requests for deleting data via concensus
* send create login packet requests to parsec
* send transfer coins via consensus and rename
* fix root_dir by using project's data dir by default
* Send UpdateLoginPacket req via consensus
* update to safe-nd 0.4.0
* refactor test to verify granulated app permissions
* allow to use multiple nodes for tests
* add consensus votes on CreateBalance requests
* send insert and delete auth keys request via…
* change usage of idata term "kind" to "data"
* introduce IDataRequest to eliminate unwraps
* handle refunds when errors are returned from the data
* deprecate Rpc::Refund to use Rpc::Response instead
* test that refunds are processed
* introduce util function to calculate refund and move
* remove explicitly-listed non-warn lints
* send CreateBalance request via consensus
* add `phase-one` feature for updates
* look up by message id
* notify all connected instances of the client
* Merge pull request #891 from ustulation/lookup-by-msg-id
* integrate with Routing
* fix clippy warnings and test failure
* fix nikita's PR #888
* Merge pull request #892 from ustulation/integrate-with-routing
* forbid unsafe and add badge
* use mock quic-p2p from routing
* add --dump-completions flag similar to that of safe-cli
* rename --dump-completions to --completions for consisten…
* fix test case
* fix smoke test failure.
* make node rng seeded from routing's
* Merge pull request #912 from maqi/use_same_rng
* add caching and other changes to GHA
* resolve non-producable issue
* Merge pull request #914 from maqi/use_same_rng
* support connection info requests from clients
* support new handshake format
* handle bootstrap request properly
* bootstrap request fixes
* update testing framework to new handshake format
* Merge pull request #911 from octol/new-bootstrap-handshake-format
* use real routing for the integration test
* make client requests handled by node network
* enable tests with feature of mock
* Small tidy up of imports for routing API cleanup
* fix clippy::needless_pass_by_value
* Re-order use and pub use statements.
* include path info in error strings
* fixup/node: formatting
* Merge pull request #919 from dirvine/vNext
* Merge pull request #909 from dan-da/completions_pr
* update routing dependecy
* upgrade routing and avoid calling node poll test function
* Merge pull request #924 from jeanphilippeD/upgade_routing_2
* Use mock-quic-p2p crate instead of routing module
* Enable test logging via pretty_env_logger
* Enable reproducible tests
* Remove pretty_env_logger dependency (use env_logger only)
* Merge pull request #925 from madadam/mock-quic-p2p
* Update codeowners
* update to latest routing API
* Merge pull request #928 from nbaksalyar/update-routing
* remove refund for login packet exists errors
* update to use routing exposed event mod
* Update to latest routing
* Update dependencies: routing, safe-nd and mock-quic-p2p
* improve error message and avoid duplicate consensus
* pull routing and qp2p with separate client channel
* Merge pull request #939 from jeanphilippeD/client_channel
* use latest version of self_update
* Update version to 0.20.1
* update routing and quic-p2p dependencies
* support --log-dir arg to optionally log to a file instead o…
* remove crate filter for logs, and make self-update to b…
* Update to latest routing
* run cargo update

### [0.20.1]
* Set execution permission on safe_vault binary before packaging for release

### [0.20.0]
* Return `AccessDenied` when apps request to insert, delete or list auth keys instead of ignoring the request.
* Use project's data directory as the root directory.
* Upgrade safe-nd dependency to 0.4.0. This includes granular permissions for applications.
* Change usage of idata term "kind" to "data".
* Introduce IDataRequest to eliminate unwraps.
* Handle refunds when errors are returned from the data handlers.
* Deprecate Rpc::Refund to use Rpc::Response instead.
* Send response to the client that sent the request instead of all connected clients.
* Use GitHub actions for build and release.

### [0.19.2]
* This is a technical release without any changes from `0.19.1`.

### [0.19.1]
* Add `verbose` command line flag.
* Fix the UX problem related to the self-update process (requiring to have a network connectivity even if a user just wanted to display the `--help` menu).
* Improve the release process, adding `.zip` and `.tar.gz` packages to distribution.

### [0.19.0]
* Rewrite the Vault code.
* Support new data types (AppendOnlyData, unpublished sequenced/unsequenced MutableData, and unpublished ImmutableData).
* Support coin operations.
* Use quic-p2p for communication with clients.
* Temporarily remove the Routing dependency.
* Refactor the personas system into a new Vault architecture.
* Use Rust stable / 2018 edition.

### [0.18.0]
* Improve Docker configuration scripts (thanks to @mattmccarty)
* Use rust 1.22.1 stable / 2017-11-23 nightly
* rustfmt 0.9.0 and clippy-0.0.174

### [0.17.2]
* Update dependencies.

### [0.17.1]
* Change test to use value of MAX_MUTABLE_DATA_ENTRIES rather than magic numbers.

### [0.17.0]
* Remove proxy rate exceed event.

### [0.16.1-2]
* Update to use Routing 0.32.2.

### [0.16.0]
* Use Routing definitions for group size and quorum.
* Add dev config options to allow running a local testnet.
* Update to use Routing 0.32.0.
* Update to use Rust Stable 1.19.0 / Nightly 2017-07-20, Clippy 0.0.144, and rustfmt 0.9.0.
* Improve DataManager tests.

### [0.15.0]
* Deprecate and remove support for Structured, PrivAppendable and PubAppendable Data.
* Add support for MutableData instead.
* MaidManagers only charge on put success now.
* MaidManagers charge by directly storing the MsgIds and counting the number of them to determine the account balance.
* MaidManagers support insertion and deletion of auth-keys to support auth-app paradigm in which all mutations on behalf of the owner of the account has to go via the MaidManagers.

### [0.14.0]
* Upgrade to routing 0.28.5.
* Migrate from rustc-serialize to serde.
* Migrate from docopt to clap.
* Implement invitation-based account creation.

### [0.13.2]
* Upgrade to routing 0.28.4.

### [0.13.1]
* Upgrade to routing 0.28.2.

### [0.13.0]
* Migrate to routing 0.28.0.
* Use a single event loop for routing and safe_vault.
* Fix issues with account creation and data requests.

### [0.12.1]
* Enforce data size caps.
* Enable new delete mechanism.

### [0.12.0]
* Handle appendable data types in data manager.
* Fix a synchronisation problem in Put/Post handling.

### [0.11.0]
* Use rust_sodium instead of sodiumoxide.
* Upgrade to routing 0.23.4, with merged safe_network_common.

### [0.10.6]
* Revert to routing 0.23.3.

### [0.10.5]
* Update the crate documentation.
* Upgrade to routing 0.25.0.

### [0.10.4]
* Remove spammy trace statement.

### [0.10.3]
* Set default Put limit to 500 and default chunk store limit to 2 GB.

### [0.10.2]
* Prevent vaults from removing existing chunk_store when terminating.

### [0.10.1]
* Fix chunk store directory handling.
* Remove remaining uses of the thread-local random number generator to make
  tests deterministic.
* Make data manager statistics less verbose to reduce spam in the logs.

### [0.10.0]
* Merge chunk_store into safe_vault and make its root directory configurable.
* Implement caching for immutable data.

### [0.9.0]
* Migrate to the mio-based Crust and the new Routing Request/Response API.
* Handle `GetAccountInfo` requests to provide information about a client's used
  and remaining chunk count.

### [0.8.1]
* Allow passing `--first` via command line to start the first Vault of a new network.
* Updated dependencies.

### [0.8.0]
* Several tweaks to churn handling in data_manager.
* Implement process to automatically build release binaries.
* Re-organise the tests to use mock Crust instead of mock Routing.
* Improve logging.
* Fix several bugs.

### [0.7.0]
* Restart routing if it failed to join the network.
* Reimplement the refresh algorithm for structured and immutable data to make it
  less wasteful and more reliable.

### [0.6.0]
* Major change of persona strategy regarding `ImmutableData` (removal of three personas)
* Major refactoring of integration tests (uses mock Crust feature)
* Default test runner to unit tests (previously run using the mock Routing feature)

### [0.5.0]
* Replaced use of local Client errors for those in safe_network_common
* Swapped dependency on mpid_messaging crate for safe_network_common dependency
* Removed Mpid tests from CI suite
* Updated some message flows
* Completed churn-handling for ImmutableDataManager
* Added many unit tests
* Fixed Clippy warnings
* Several bugfixes

### [0.4.0]
* Accommodated updates to dependencies' APIs
* Ensured that the network can correctly handle Clients doing a Get for ImmutableData immediately after doing a Put
* Reduced `REPLICANTS` and `MIN_REPLICANTS` to 4

### [0.3.0]
* Major refactor to accommodate changed Routing

### [0.1.6]
* Default to use real Routing rather than the mock
* Updated config file to match Crust changes
* Refactored flow for put_response
* Added churn tests
* Refactored returns from most persona functions to not use Result

### [0.1.5]
* Major refactor of production code and tests to match Routing's new API, allowing testing on a real network rather than a mock
* Updated installers to match Crust's config/bootstrap file changes
* Added tarball to packages being generated
* Dropped usage of feature-gated items

### [0.1.4]
* [MAID-1283](https://maidsafe.atlassian.net/browse/MAID-1283) Rename repositories from "maidsafe_" to "safe_"

### [0.1.3]
* [MAID-1186](https://maidsafe.atlassian.net/browse/MAID-1186) Handling of unified Structrued Data
    - [MAID-1187](https://maidsafe.atlassian.net/browse/MAID-1187) Updating Version Handler
    - [MAID-1188](https://maidsafe.atlassian.net/browse/MAID-1188) Updating other personas if required

### [0.1.2] - code clean up
* [MAID 1185](https://maidsafe.atlassian.net/browse/MAID-1185) using unwrap unsafely

### [0.1.1]
* Updated dependencies' versions
* Fixed lint warnings caused by latest Rust nightly
* [Issue 117](https://github.com/maidsafe/safe_vault/issues/117) meaningful type_tag
* [PR 124](https://github.com/maidsafe/safe_vault/pull/124) integration test with client
    - client log in / log out
    - complete put flow
    - complete get flow

### [0.1.0] - integrate with routing and safecoin farming initial work [rust-2 Sprint]
* [MAID-1107](https://maidsafe.atlassian.net/browse/MAID-1107) Rename actions (changes in routing v0.1.60)
* [MAID-1008](https://maidsafe.atlassian.net/browse/MAID-1008) Documentation
    - [MAID-1009](https://maidsafe.atlassian.net/browse/MAID-1009) Personas
        - ClientManager : MaidManager
        - NodeManager : PmidManager
        - Node : PmidNode
        - NAE : DataManager, VersionHandler
    - [MAID-1011](https://maidsafe.atlassian.net/browse/MAID-1011) Accounting
        - MaidAccount : create, update and monitor
        - PmidAccount : create, update and monitor
    - [MAID-1010](https://maidsafe.atlassian.net/browse/MAID-1010) Flows
        - PutData / PutResponse
        - GetData / GetResponse
        - PostData
* [MAID-1013](https://maidsafe.atlassian.net/browse/MAID-1013) Complete unfinished code (if it will be covered by the later-on tasks in this sprint, explicitly mention it as in-code TODO comment), especially in vault.rs
    - [MAID-1109](https://maidsafe.atlassian.net/browse/MAID-1109) handle_get_key
    - [MAID-1112](https://maidsafe.atlassian.net/browse/MAID-1112) handle_put_response
    - [MAID-1113](https://maidsafe.atlassian.net/browse/MAID-1113) handle_cache_get
    - [MAID-1113](https://maidsafe.atlassian.net/browse/MAID-1113) handle_cache_put
* [MAID-1014](https://maidsafe.atlassian.net/browse/MAID-1014) Integration test with new routing and crust (vaults bootstrap and network setup)
    - [MAID-1028](https://maidsafe.atlassian.net/browse/MAID-1028) local joining test (process counting)
    - [MAID-1016](https://maidsafe.atlassian.net/browse/MAID-1016) network example (nodes populating)
* [MAID-1012](https://maidsafe.atlassian.net/browse/MAID-1012) SafeCoin farming (new persona may need to be introduced, the task needs to be ‘expandable’ ) documentation
    - farming
    - account
* [MAID-1021](https://maidsafe.atlassian.net/browse/MAID-1021) Implement handling for Safecoin farming rate
    - Farming rate determined by the Sacrificial copies.
    - Farming rate drops when more copies are available and rises when less copies are available.

### [0.0.0 - 0.0.3]
* VaultFacade initial implementation
* Chunkstore implementation and test
* Initial Persona implementation :
    - Implement MaidManager and test
    - Implement DataManager and test
    - Implement PmidManager and test
    - Implement PmidNode and test
    - Implement VersionHandler
* Flow related work :
    - Complete simple Put flow and test
    - Complete simple Get flow and test
    - Complete Create Maid Account Flow
* Installers (linux deb/rpm 32/64 bit, Windows 32 / 64. OSX)
* Coverage analysis
