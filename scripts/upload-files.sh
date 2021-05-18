#!/bin/bash

# Uploads 20 files of 1MB each
echo "creating new keys"
~/.safe/cli/safe keys create --test-coins --preload 1000000 --for-cli
echo "keys creted and preloaded"
timestamp=$(date +"%T")
mkdir -p files
mkdir -p addresses
for i in {0..20}; do
	dd if=/dev/urandom of=files/randomfile-$timestamp-$i bs=1M count=1
	echo "file $i generated"
	~/.safe/cli/safe files put files/randomfile-$timestamp-$i  --json > addresses/data-address-$timestamp-$i
done

