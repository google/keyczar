#!/usr/bin/python2.4
#
# Copyright 2008 Google Inc. All Rights Reserved.
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

"""Utility functions for keyczar package."""

__author__ = """arkajit.dey@gmail.com (Arkajit Dey)"""

import errors

from Crypto.Util import randpool
import sha
import base64
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from pyasn1.codec.der import decoder

#RSAPrivateKey ::= SEQUENCE {
#  version Version,
#  modulus INTEGER, -- n
#  publicExponent INTEGER, -- e
#  privateExponent INTEGER, -- d
#  prime1 INTEGER, -- p
#  prime2 INTEGER, -- q
#  exponent1 INTEGER, -- d mod (p-1)
#  exponent2 INTEGER, -- d mod (q-1)
#  coefficient INTEGER -- (inverse of q) mod p }
#
#Version ::= INTEGER
RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
RSA_PARAMS = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'invq']
DSA_OID = univ.ObjectIdentifier('1.2.840.10040.4.1')
DSA_PARAMS = ['p', 'q', 'g']  # only algorithm params, not public/private keys

#PrivateKeyInfo ::= SEQUENCE {
#  version Version,
#
#  privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
#  privateKey PrivateKey,
#  attributes [0] IMPLICIT Attributes OPTIONAL }
#
#Version ::= INTEGER
#
#PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
#
#PrivateKey ::= OCTET STRING
#
#Attributes ::= SET OF Attribute
def ParsePkcs8(pkcs8):
  seq = decoder.decode(Decode(pkcs8))[0]
  if len(seq) != 3:  # need three fields in PrivateKeyInfo
    raise errors.KeyczarError("Illegal PKCS8 String.")
  version = int(seq.getComponentByPosition(0))
  if version != 0:
      raise errors.KeyczarError("Unrecognized PKCS8 Version")
  oid = seq.getComponentByPosition(1).getComponentByPosition(0)
  alg_params = seq.getComponentByPosition(1).getComponentByPosition(1)
  key = decoder.decode(seq.getComponentByPosition(2))[0]
  # Component 2 is an OCTET STRING which is further decoded
  params = {}
  if oid == RSA_OID:
    version = int(key.getComponentByPosition(0))
    if version != 0:
      raise errors.KeyczarError("Unrecognized RSA Private Key Version")
    for i in range(len(RSA_PARAMS)):
      params[RSA_PARAMS[i]] = int(key.getComponentByPosition(i+1))
  elif oid == DSA_OID:
    for i in range(len(DSA_PARAMS)):
      params[DSA_PARAMS[i]] = int(alg_params.getComponentByPosition(i))
    params['x'] = int(key)
  else:
    raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")
  return params

def ExportRsaPkcs8(params):
  seq = univ.Sequence().setComponentByPosition(0, univ.Integer(0))  # version
  oid = univ.Sequence().setComponentByPosition(0, RSA_OID)
  oid.setComponentByPosition(1, univ.Null())
  key = univ.Sequence().setComponentByPosition(0, univ.Integer(0))  # version
  for i in range(len(RSA_PARAMS)):
    key.setComponentByPosition(i+1, univ.Integer(params[RSA_PARAMS[i]]))
  octkey = encoder.encode(key)
  seq.setComponentByPosition(1, oid)
  seq.setComponentByPosition(2, univ.OctetString(octkey))

def ExportDsaPkcs8(params):
  seq = univ.Sequence().setComponentByPosition(0, univ.Integer(0))  # version
  alg_params = univ.Sequence()
  for i in range(len(DSA_PARAMS)):
    alg_params.setComponentByPosition(i, univ.Integer(params[DSA_PARAMS[i]]))
  oid = univ.Sequence().setComponentByPosition(0, DSA_OID)
  oid.setComponentByPosition(1, alg_params)
  octkey = encoder.encode(univ.Integer(params['x']))
  seq.setComponentByPosition(1, oid)
  seq.setComponentByPosition(2, univ.OctetString(octkey))

#NOTE: not full X.509 certificate, just public key info
#SubjectPublicKeyInfo  ::=  SEQUENCE  {
#        algorithm            AlgorithmIdentifier,
#        subjectPublicKey     BIT STRING  }
def ParseX509(x509):
  seq = decoder.decode(Decode(x509))[0]
  if len(seq) != 2:  # need two fields in SubjectPublicKeyInfo
    raise errors.KeyczarError("Illegal X.509 String.")
  oid = seq.getComponentByPosition(0).getComponentByPosition(0)
  alg_params = seq.getComponentByPosition(0).getComponentByPosition(1)
  pubkey = decoder.decode(univ.OctetString(BinToBytes(seq.
                            getComponentByPosition(1).prettyPrint()[1:-2])))[0]
  # Component 1 should be a BIT STRING, get raw bits by discarding extra chars,
  # then convert to OCTET STRING which can be ASN.1 decoded
  params = {}
  if oid == RSA_OID:
    params['n'] = int(pubkey.getComponentByPosition(0))
    params['e'] = int(pubkey.getComponentByPosition(1))
  elif oid == DSA_OID:
    for i in range(len(DSA_PARAMS)):
      params[DSA_PARAMS[i]] = int(alg_params.getComponentByPosition(i))
    params['y'] = int(pubkey)
  else:
    raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")
  return params

def ExportRsaX509(params):
  seq = univ.Sequence()
  oid = univ.Sequence().setComponentByPosition(0, RSA_OID)
  oid.setComponentByPosition(1, univ.Null())
  key = univ.Sequence()
  key.setComponentByPosition(0, univ.Integer(params['n']))
  key.setComponentByPosition(1, univ.Integer(params['e']))
  binkey = BytesToBin(encoder.encode(key))
  pubkey = univ.BitString("'%s'B" % binkey)  # needs to be a BIT STRING
  seq.setComponentByPosition(0, oid)
  seq.setComponentByPosition(1, pubkey)
  return Encode(encoder.encode(seq))

def ExportDsaX509(params):
  seq = univ.Sequence()
  alg_params = univ.Sequence()
  for i in range(len(DSA_PARAMS)):
    alg_params.setComponentByPosition(i, univ.Integer(params[DSA_PARAMS[i]]))
  oid = univ.Sequence().setComponentByPosition(0, DSA_OID)
  oid.setComponentByPosition(1, alg_params)
  binkey = BytesToBin(encoder.encode(univ.Integer(params['y'])))
  pubkey = univ.BitString("'%s'B" % binkey)  # needs to be a BIT STRING
  seq.setComponentByPosition(0, oid)
  seq.setComponentByPosition(1, pubkey)
  return Encode(encoder.encode(seq))

def BinToBytes(bits):
  """Convert bit string to byte string."""
  r = len(bits) % 8
  if r != 0:
    bits = (8-r)*'0' + bits
  octets = [bits[8*i:8*(i+1)] for i in range(len(bits)/8)]
  bytes = [chr(int(x, 2)) for x in octets]
  return "".join(bytes)

def BytesToBin(bytes):
  """Convert byte string to bit string."""
  return "".join([IntToBin(ord(byte)) for byte in bytes])

def IntToBin(n):
  if n == 0 or n == 1:
    return str(n)
  elif n % 2 == 0:
    return IntToBin(n/2) + "0"
  else:
    return IntToBin(n/2) + "1"

def IntToBytes(n):
  """Return byte string of 4 big-endian ordered bytes representing n."""
  bytes = [m % 256 for m in [n >> 24, n >> 16, n >> 8, n]]
  return "".join([chr(b) for b in bytes])  # byte array to byte string

def RandBytes(n):
  """Return n random bytes."""
  return randpool.RandomPool(512).get_bytes(n)

def Hash(inputs):
  """Return a SHA-1 hash over a list of inputs."""
  md = sha.new()
  for i in inputs:
    md.update(i)
  return md.digest()

def Encode(s):
  """Return Base64 encoding of s. Suppress padding characters (=).
  
  Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
  unicode to string type first.
  
  Parameters:
    s: string to encode as Base64
  
  Returns:
    Base64 representation of s.
  """
  return base64.urlsafe_b64encode(str(s)).replace("=", "")
  

def Decode(s):
  """Return decoded version of given Base64 string. Ignore whitespace.
  
  Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
  unicode to string type first.
  
  Parameters:
    s: Base64 string to decode
  
  Returns:
    original string that was encoded as Base64
  
  Raises:
    Base64DecodingError: If length of string (ignoring whitespace) is one more
      than a multiple of four.
  """
  s = str(s.replace(" ", ""))  # kill whitespace, make string (not unicode)
  d = len(s) % 4
  if d == 1:
    raise errors.Base64DecodingError()
  elif d == 2:
    s += "=="
  elif d == 3:
    s += "="
  return base64.urlsafe_b64decode(s)