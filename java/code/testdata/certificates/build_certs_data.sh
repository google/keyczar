#!/bin/sh
#
# Copyright 2011 Google Inc.  All Rights Reserved
#
# Author: swillden@google.com (Shawn Willden)
#
# This script was used to generate all of the test keys and certificatees
# in testdata/certificates.  It is included here primarily for documentation
# purposes, but could be used to regenerate the keys and certs if requited.

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
  keyczart create --location="$KSET" --purpose="$PURP" --asymmetric="$ALGO"
  keyczart addkey --location="$KSET" --status=primary

  echo "Exporting $KSET key pair to PEM file"
  keyczart exportkey --location="$KSET" --dest="$KSET".pem --passphrase="pass"

  echo "Exporting $KSET public key to keyczar keyset $KSET-pub"
  mkdir "$KSET"-pub
  keyczart pubkey --location="$KSET" --destination="$KSET"-pub

  echo "Exporting $KSET public key to PEM file"
  openssl $ALGO -in "$KSET".pem -passin "pass:pass" -pubout -out "$KSET"-pub.pem

  echo "Exporting $KSET public key to DER file"
  openssl $ALGO -in "$KSET".pem -passin "pass:pass" -pubout -outform DER -out "$KSET"-pub.der

  echo "Converting $KSET key pair PEM file to DER file"
  openssl $ALGO -outform DER -in "$KSET".pem -out "$KSET".der \
    -passin "pass:pass" -passout "pass:pass" >> /dev/null

  echo "Creating $KSET self-signed certificate (PEM format)"
  openssl req -new -x509 -key "$KSET".pem -out "$KSET"-crt.pem -days 3650 \
    -config cert.cfg

  echo "Creating $KSET self-signed certificate (DER format)"
  openssl req -new -x509 -key "$KSET".pem -out "$KSET"-crt.der -days 3650 \
    -config cert.cfg -outform DER
}

die() {
  echo $1
  exit 1
}

which keyczart > /dev/null || die "keyczart not found, aborting"
which openssl > /dev/null || die "openssl not found, aborting"

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
