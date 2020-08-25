SHELL := /bin/bash
SAFE_VAULT_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
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
	docker run --name "safe-vault-build-${UUID}" \
		-v "${PWD}":/usr/src/safe-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		cargo build --release
	docker cp "safe-vault-build-${UUID}":/target .
	docker rm "safe-vault-build-${UUID}"
else
	cargo build --release
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

build-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-vault-build:build
	docker build -f Dockerfile.build -t maidsafe/safe-vault-build:build \
		--build-arg build_type="non-mock" .

build-mock-container:
	rm -rf target/
	docker rmi -f maidsafe/safe-vault-build:build-mock
	docker build -f Dockerfile.build -t maidsafe/safe-vault-build:build-mock \
		--build-arg build_type="mock" .

push-container:
	docker push maidsafe/safe-vault-build:build

push-mock-container:
	docker push maidsafe/safe-vault-build:build-mock

musl:
ifneq ($(UNAME_S),Linux)
	@echo "This target only applies to Linux."
	@exit 1
endif
	rm -rf target
	rm -rf artifacts
	mkdir artifacts
	docker run --name "safe-vault-build-${UUID}" \
		-v "${PWD}":/usr/src/safe_vault:Z \
		-e CC=musl-gcc \
		-e OPENSSL_INCLUDE_DIR=/usr/local/musl/include \
		-e OPENSSL_LIB_DIR=/usr/local/musl/lib \
		-e RUSTFLAGS='-C linker=musl-gcc' \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		cargo build --release --target x86_64-unknown-linux-musl --verbose
	docker cp "safe-vault-build-${UUID}":/target .
	docker rm "safe-vault-build-${UUID}"
	find target/x86_64-unknown-linux-musl/release \
		-maxdepth 1 -type f -exec cp '{}' artifacts \;

package-commit_hash-artifacts-for-deploy:
	rm -f *.tar
	rm -rf ${DEPLOY_PATH}
	mkdir -p ${DEPLOY_PROD_PATH}

	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
        -cvf safe_vault-${COMMIT_HASH}-x86_64-unknown-linux-musl.tar safe_vault
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
        -cvf safe_vault-${COMMIT_HASH}-x86_64-pc-windows-msvc.tar safe_vault.exe
	tar -C artifacts/prod/x86_64-apple-darwin/release \
        -cvf safe_vault-${COMMIT_HASH}-x86_64-apple-darwin.tar safe_vault

	mv *.tar ${DEPLOY_PROD_PATH}

.ONESHELL:
package-version-artifacts-for-deploy:
	rm -f *.zip *.tar.gz
	rm -rf ${DEPLOY_PATH}
	mkdir -p ${DEPLOY_PROD_PATH}

	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.zip \
		artifacts/prod/x86_64-unknown-linux-musl/release/safe_vault
	zip -j safe_vault-latest-x86_64-unknown-linux-musl.zip \
		artifacts/prod/x86_64-unknown-linux-musl/release/safe_vault
	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-msvc.zip \
		artifacts/prod/x86_64-pc-windows-msvc/release/safe_vault.exe
	zip -j safe_vault-latest-x86_64-pc-windows-msvc.zip \
		artifacts/prod/x86_64-pc-windows-msvc/release/safe_vault.exe
	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.zip \
		artifacts/prod/x86_64-apple-darwin/release/safe_vault
	zip -j safe_vault-latest-x86_64-apple-darwin.zip \
		artifacts/prod/x86_64-apple-darwin/release/safe_vault

	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.tar.gz safe_vault
	tar -C artifacts/prod/x86_64-unknown-linux-musl/release \
		-zcvf safe_vault-latest-x86_64-unknown-linux-musl.tar.gz safe_vault
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-msvc.tar.gz safe_vault.exe
	tar -C artifacts/prod/x86_64-pc-windows-msvc/release \
		-zcvf safe_vault-latest-x86_64-pc-windows-msvc.tar.gz safe_vault.exe
	tar -C artifacts/prod/x86_64-apple-darwin/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.tar.gz safe_vault
	tar -C artifacts/prod/x86_64-apple-darwin/release \
		-zcvf safe_vault-latest-x86_64-apple-darwin.tar.gz safe_vault

	mv *.zip ${DEPLOY_PROD_PATH}
	mv *.tar.gz ${DEPLOY_PROD_PATH}
