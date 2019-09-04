SHELL := /bin/bash
SAFE_VAULT_VERSION := $(shell grep "^version" < Cargo.toml | head -n 1 | awk '{ print $$3 }' | sed 's/\"//g')
USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)
UNAME_S := $(shell uname -s)
PWD := $(shell echo $$PWD)
UUID := $(shell uuidgen | sed 's/-//g')
S3_BUCKET := safe-jenkins-build-artifacts
GITHUB_REPO_OWNER := maidsafe
GITHUB_REPO_NAME := safe_vault

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

build-clean:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-vault-build-${UUID}" \
		-v "${PWD}":/usr/src/safe-cli:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		bash -c "rm -rf /target/release && cargo build --release"
	docker cp "safe-vault-build-${UUID}":/target .
	docker rm "safe-vault-build-${UUID}"
else
	rm -rf target
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

clippy:
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-vault-build-${UUID}" \
		-v "${PWD}":/usr/src/safe_vault:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		./scripts/clippy --verbose
else
	./scripts/clippy --verbose
endif

test:
	rm -rf artifacts
	mkdir artifacts
ifeq ($(UNAME_S),Linux)
	docker run --name "safe-vault-build-${UUID}" \
		-v "${PWD}":/usr/src/safe_vault:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		./scripts/tests --verbose
	docker cp "safe-vault-build-${UUID}":/target .
	docker rm "safe-vault-build-${UUID}"
else
	# The explicit `cargo build` is because the test script does not actually
	# produce a binary to distribute.
	cargo build --release
	./scripts/tests --verbose
endif
	find target/release -maxdepth 1 -type f -exec cp '{}' artifacts \;

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

package-build-artifacts:
ifndef SAFE_VAULT_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SAFE_VAULT_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SAFE_VAULT_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SAFE_VAULT_BUILD_NUMBER to a valid build number."
	@exit 1
endif
ifndef SAFE_VAULT_BUILD_OS
	@echo "A value must be supplied for SAFE_VAULT_BUILD_OS."
	@echo "Valid values are 'linux' or 'windows' or 'macos'."
	@exit 1
endif
	$(eval ARCHIVE_NAME := ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-${SAFE_VAULT_BUILD_OS}-x86_64.tar.gz)
	tar -C artifacts -zcvf ${ARCHIVE_NAME} .
	rm artifacts/**
	mv ${ARCHIVE_NAME} artifacts

retrieve-all-build-artifacts:
ifndef SAFE_VAULT_BRANCH
	@echo "A branch or PR reference must be provided."
	@echo "Please set SAFE_VAULT_BRANCH to a valid branch or PR reference."
	@exit 1
endif
ifndef SAFE_VAULT_BUILD_NUMBER
	@echo "A build number must be supplied for build artifact packaging."
	@echo "Please set SAFE_VAULT_BUILD_NUMBER to a valid build number."
	@exit 1
endif
	rm -rf artifacts
	mkdir -p artifacts/linux/release
	mkdir -p artifacts/win/release
	mkdir -p artifacts/macos/release
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-linux-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-windows-x86_64.tar.gz .
	aws s3 cp --no-sign-request --region eu-west-2 s3://${S3_BUCKET}/${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-macos-x86_64.tar.gz .
	tar -C artifacts/linux/release -xvf ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-linux-x86_64.tar.gz
	tar -C artifacts/win/release -xvf ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-windows-x86_64.tar.gz
	tar -C artifacts/macos/release -xvf ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-macos-x86_64.tar.gz
	rm ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-linux-x86_64.tar.gz
	rm ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-windows-x86_64.tar.gz
	rm ${SAFE_VAULT_BRANCH}-${SAFE_VAULT_BUILD_NUMBER}-safe_vault-macos-x86_64.tar.gz

package-commit_hash-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir deploy
	tar -C artifacts/linux/release -cvf safe_vault-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-musl.tar safe_vault
	tar -C artifacts/win/release -cvf safe_vault-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar safe_vault.exe
	tar -C artifacts/macos/release -cvf safe_vault-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar safe_vault
	mv safe_vault-$$(git rev-parse --short HEAD)-x86_64-unknown-linux-musl.tar deploy
	mv safe_vault-$$(git rev-parse --short HEAD)-x86_64-pc-windows-gnu.tar deploy
	mv safe_vault-$$(git rev-parse --short HEAD)-x86_64-apple-darwin.tar deploy

package-version-artifacts-for-deploy:
	rm -f *.tar
	rm -rf deploy
	mkdir deploy
	cd deploy
	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-gnu.zip \
		../../artifacts/linux/release/safe
	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.zip \
		../../artifacts/win/release/safe.exe
	zip -j safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.zip \
		../../artifacts/macos/release/safe
	tar -C ../../artifacts/linux/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.tar.gz safe
	tar -C ../../artifacts/win/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.tar.gz safe.exe
	tar -C ../../artifacts/macos/release \
		-zcvf safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.tar.gz safe

deploy-github-release:
ifndef GITHUB_TOKEN
	@echo "Please set GITHUB_TOKEN to the API token for a user who can create releases."
	@exit 1
endif
	github-release release \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe-vault" \
		--description "$$(./scripts/get_release_description.sh ${SAFE_VAULT_VERSION})"
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.zip" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.zip
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.zip" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.zip
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.zip" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.zip
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-unknown-linux-musl.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.tar.gz" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-pc-windows-gnu.tar.gz
	github-release upload \
		--user ${GITHUB_REPO_OWNER} \
		--repo ${GITHUB_REPO_NAME} \
		--tag ${SAFE_VAULT_VERSION} \
		--name "safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.tar.gz" \
		--file deploy/safe_vault-${SAFE_VAULT_VERSION}-x86_64-apple-darwin.tar.gz

publish:
ifndef CRATES_IO_TOKEN
	@echo "A login token for crates.io must be provided."
	@exit 1
endif
	rm -rf artifacts deploy
	docker run --rm -v "${PWD}":/usr/src/safe_vault:Z \
		-u ${USER_ID}:${GROUP_ID} \
		maidsafe/safe-vault-build:build \
		/bin/bash -c "cargo login ${CRATES_IO_TOKEN} && cargo package && cargo publish"

retrieve-cache:
ifndef SAFE_VAULT_BRANCH
	@echo "A branch reference must be provided."
	@echo "Please set SAFE_VAULT_BRANCH to a valid branch reference."
	@exit 1
endif
ifeq ($(OS),Windows_NT)
	aws s3 cp \
		--no-sign-request \
		--region eu-west-2 \
		s3://${S3_BUCKET}/safe_vault-${SAFE_VAULT_BRANCH}-windows-cache.tar.gz .
	mkdir target
	tar -C target -xvf safe_vault-${SAFE_VAULT_BRANCH}-windows-cache.tar.gz
	rm safe_vault-${SAFE_VAULT_BRANCH}-windows-cache.tar.gz
endif
