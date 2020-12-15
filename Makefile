SHELL := /bin/bash
SN_NODE_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
COMMIT_HASH := $(shell git rev-parse --short HEAD)
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')
DEPLOY_PATH := deploy
DEPLOY_PROD_PATH := ${DEPLOY_PATH}/prod

build:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "sn-node-build-${UUID}" \
		-v "${PWD}":/usr/src/sn_cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/sn-node-build:build \
		cargo build --release
	docker cp "sn-node-build-${UUID}":/target .
	docker rm "sn-node-build-${UUID}"
else
	cargo build --release
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-container:
	rm -rf target/
	docker rmi -f maidsafe/sn-node-build:build
	docker build -f Dockerfile.build -t maidsafe/sn-node-build:build \
		--build-arg build_type="non-mock" .

build-mock-container:
	rm -rf target/
	docker rmi -f maidsafe/sn-node-build:build-mock
	docker build -f Dockerfile.build -t maidsafe/sn-node-build:build-mock \
		--build-arg build_type="mock" .

push-container:
	docker push maidsafe/sn-node-build:build

push-mock-container:
	docker push maidsafe/sn-node-build:build-mock

musl:
ifneq ($(UNAME_S),Linux)
	@echo "This target only applies to Linux."
	@exit 1
endif
	rm -rf target
	rm -rf artifacts
	mkdir artifacts
	sudo apt update -y && sudo apt install -y musl-tools
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl --verbose
	find target/x86_64-unknown-linux-musl/release \
		-maxdepth 1 -type f -exec cp '{}' artifacts \;		

package-commit_hash-artifacts-for-deploy:
	rm -f *.tar
	rm -rf ${DEPLOY_PATH}
	mkdir -p ${DEPLOY_PROD_PATH}

	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
        -cvf sn_node-${COMMIT_HASH}-x86_64-unknown-linux-musl.tar sn_node
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
        -cvf sn_node-${COMMIT_HASH}-x86_64-pc-windows-msvc.tar sn_node.exe
	tar -C artifacts/prod/x86_64-apple-darwin/release \
        -cvf sn_node-${COMMIT_HASH}-x86_64-apple-darwin.tar sn_node

	mv *.tar ${DEPLOY_PROD_PATH}

.ONESHELL:
package-version-artifacts-for-deploy:
	rm -f *.zip *.tar.gz
	rm -rf ${DEPLOY_PATH}
	mkdir -p ${DEPLOY_PROD_PATH}

	zip -j sn_node-${SN_NODE_VERSION}-x86_64-unknown-linux-musl.zip \
		artifacts/prod/x86_64-unknown-linux-musl/release/sn_node
	zip -j sn_node-latest-x86_64-unknown-linux-musl.zip \
		artifacts/prod/x86_64-unknown-linux-musl/release/sn_node
	zip -j sn_node-${SN_NODE_VERSION}-x86_64-pc-windows-msvc.zip \
		artifacts/prod/x86_64-pc-windows-msvc/release/sn_node.exe
	zip -j sn_node-latest-x86_64-pc-windows-msvc.zip \
		artifacts/prod/x86_64-pc-windows-msvc/release/sn_node.exe
	zip -j sn_node-${SN_NODE_VERSION}-x86_64-apple-darwin.zip \
		artifacts/prod/x86_64-apple-darwin/release/sn_node
	zip -j sn_node-latest-x86_64-apple-darwin.zip \
		artifacts/prod/x86_64-apple-darwin/release/sn_node

	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
		-zcvf sn_node-${SN_NODE_VERSION}-x86_64-unknown-linux-musl.tar.gz sn_node
	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
		-zcvf sn_node-latest-x86_64-unknown-linux-musl.tar.gz sn_node
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
		-zcvf sn_node-${SN_NODE_VERSION}-x86_64-pc-windows-msvc.tar.gz sn_node.exe
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
		-zcvf sn_node-latest-x86_64-pc-windows-msvc.tar.gz sn_node.exe
	tar -C artifacts/prod/x86_64-apple-darwin/release \
		-zcvf sn_node-${SN_NODE_VERSION}-x86_64-apple-darwin.tar.gz sn_node
	tar -C artifacts/prod/x86_64-apple-darwin/release \
		-zcvf sn_node-latest-x86_64-apple-darwin.tar.gz sn_node

	mv *.zip ${DEPLOY_PROD_PATH}
	mv *.tar.gz ${DEPLOY_PROD_PATH}
