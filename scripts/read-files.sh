#!/bin/bash

for address in $(ls addresses/data-address-*); do
    safe cat $(jq -r '.[0]' $address)
    safe cat $(jq -r '.[1][][1]' $address) > /dev/null
done