#!/bin/sh

ROOT_KEYSETS=/tmp/kz_keysets

if [ ! -d "$ROOT_KEYSETS" ]; then
   mkdir -p $ROOT_KEYSETS
fi

# C++
make
./testdata_gen $ROOT_KEYSETS
./basic_encrypt $ROOT_KEYSETS/aes
./basic_encrypt $ROOT_KEYSETS/rsa
./basic_sign $ROOT_KEYSETS/hmac
./basic_sign $ROOT_KEYSETS/dsa
./basic_sign $ROOT_KEYSETS/ecdsa
./basic_sign $ROOT_KEYSETS/rsa-sign
make clean

# Python
python basic_encrypt.py $ROOT_KEYSETS/aes
python basic_encrypt.py $ROOT_KEYSETS/rsa
python basic_sign.py $ROOT_KEYSETS/hmac
python basic_sign.py $ROOT_KEYSETS/dsa
python basic_sign.py $ROOT_KEYSETS/ecdsa
python basic_sign.py $ROOT_KEYSETS/rsa-sign

rm -rf $ROOT_KEYSETS

