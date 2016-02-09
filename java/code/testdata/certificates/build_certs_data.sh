#!/bin/sh
#
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# This script was used to generate all of the test keys and certificatees
# in testdata/certificates.  It is included here primarily for documentation
# purposes, but could be used to regenerate the keys and certs if required.

KEYCZART=../../../../cpp/src/scons-out/dbg-linux/staging/keyczart
OPENSSL=openssl

build_keys_and_cert() {
  local ALGO="$1"
  local PURP="$2"
  local KSET="$ALGO-$PURP"

  echo
  echo "#####################################################"
  echo "# Creating $KSET test data"
  echo "#####################################################"
  echo
  echo "Creating $KSET key pair"
  mkdir "$KSET"
  $KEYCZART create --location="$KSET" --purpose="$PURP" --asymmetric="$ALGO"
  $KEYCZART addkey --location="$KSET" --status=primary --size=1024

  echo "Exporting $KSET key pair to SSLEay PEM file"
  $KEYCZART exportkey --location="$KSET" --dest="$KSET".pem --passphrase="pass"

  echo "Creating $KSET self-signed certificate (PEM format)"
  $OPENSSL req -new -x509 -key "$KSET".pem -out "$KSET"-crt.pem -days 3650 \
      -config cert.cfg

  echo "Creating $KSET self-signed certificate (DER format)"
  $OPENSSL req -new -x509 -key "$KSET".pem -out "$KSET"-crt.der -days 3650 \
      -config cert.cfg -outform DER

  echo "Converting $KSET key pair to PKCS#8 (PEM format)"
  $OPENSSL pkcs8 -topk8 -in "$KSET".pem -out "$KSET"-pkcs8.pem -passin pass:pass \
      -passout pass:pass

  echo "Converting $KSET key pair to PKCS#8 (DER format)"
  $OPENSSL pkcs8 -topk8 -in "$KSET".pem -out "$KSET"-pkcs8.der -passin pass:pass \
      -passout pass:pass -outform DER

  echo "Deleting $KSET SSLEay PEM file"
  rm "$KSET".pem

  echo "Exporting $KSET public key to keyczar keyset $KSET-pub"
  mkdir "$KSET"-pub
  $KEYCZART pubkey --location="$KSET" --destination="$KSET"-pub
}

die() {
  echo $1
  exit 1
}

which $KEYCZART > /dev/null || die "keyczart not found, aborting"
which $OPENSSL > /dev/null || die "openssl not found, aborting"

rm -rf rsa* dsa* cert.cfg

cat > cert.cfg <<-EOF
	[ req ]
	distinguished_name=req_distinguished_name
	prompt=no
	input_password=pass

	[ req_distinguished_name ]
	C=US
	ST=Colorado
	L=Boulder
	O=Google Inc.
	OU=Commerce
	CN=Propeller Head
	emailAddress=phead@google.com
EOF

build_keys_and_cert rsa crypt
build_keys_and_cert rsa sign
build_keys_and_cert dsa sign

rm cert.cfg
