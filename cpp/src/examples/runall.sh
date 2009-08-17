#!/bin/sh
#
# This script compiles and runs most of the examples contained
# in this directory.
#
ROOT_KEYSETS_JSON=/tmp/kz_json_keysets

## JSON
if [ ! -d "$ROOT_KEYSETS_JSON" ]; then
    mkdir -p $ROOT_KEYSETS_JSON
fi

# C++
make
./testdata_gen $ROOT_KEYSETS_JSON
./basic_encrypt $ROOT_KEYSETS_JSON/aes
./basic_encrypt $ROOT_KEYSETS_JSON/rsa
./basic_sign $ROOT_KEYSETS_JSON/hmac
./basic_sign $ROOT_KEYSETS_JSON/dsa
./basic_sign $ROOT_KEYSETS_JSON/ecdsa
./basic_sign $ROOT_KEYSETS_JSON/rsa-sign
make clean

# Python
python basic_encrypt.py $ROOT_KEYSETS_JSON/aes
python basic_encrypt.py $ROOT_KEYSETS_JSON/rsa
python basic_sign.py $ROOT_KEYSETS_JSON/hmac
python basic_sign.py $ROOT_KEYSETS_JSON/dsa
python basic_sign.py $ROOT_KEYSETS_JSON/ecdsa
python basic_sign.py $ROOT_KEYSETS_JSON/rsa-sign

rm -rf $ROOT_KEYSETS_JSON
