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
from pyasn1.type import namedtype
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
RSA_SPEC = univ.Sequence(componentType=namedtype.NamedTypes(
                              namedtype.NamedType('version', univ.Integer()), 
                              namedtype.NamedType('n', univ.Integer()), 
                              namedtype.NamedType('e', univ.Integer()), 
                              namedtype.NamedType('d', univ.Integer()), 
                              namedtype.NamedType('p', univ.Integer()), 
                              namedtype.NamedType('q', univ.Integer()), 
                              namedtype.NamedType('dp', univ.Integer()), 
                              namedtype.NamedType('dq', univ.Integer()), 
                              namedtype.NamedType('invq', univ.Integer())
                        ))  # Don't need this anymore, can use position nums
RSA_PARAMS = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'invq']
DSA_OID = univ.ObjectIdentifier('1.2.840.10040.4.1')
DSA_SPEC = None  # TODO: fill in

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
def ParsePkcs8(bytes):
  seq = decoder.decode(bytes)[0]
  if len(seq) != 3:  # need three fields in PrivateKeyInfo
    raise errors.KeyczarError("Illegal PKCS8 String.")
  version = int(seq.getComponentByPosition(0))
  if version != 0:
      raise errors.KeyczarError("Unrecognized PKCS8 Version")
  oid = seq.getComponentByPosition(1).getComponentByPosition(0)
  alg_params = seq.getComponentByPosition(1).getComponentByPosition(1)
  pkey = seq.getComponentByPosition(2)
  if oid == RSA_OID:
    key = decoder.decode(pkey, asn1Spec=RSA_SPEC)[0]
    params = {}
    version = int(key.getComponentByPosition(0))
    if version != 0:
      raise errors.KeyczarError("Unrecognized RSA Private Key Version")
    for i in range(len(RSA_PARAMS)):
      params[RSA_PARAMS[i]] = int(key.getComponentByPosition(i+1))
    return params
  elif oid == DSA_OID:
    params = {'p': int(alg_params.getComponentByPosition(0)),
              'q': int(alg_params.getComponentByPosition(1)),
              'g': int(alg_params.getComponentByPosition(2))}
    params['y'] = int(decoder.decode(pkey)[0])
    params['x'] = None
    #TODO: decoding pkey just gives an octet string of an integer, figure
    # out if this is x or y and where the other one is
  else:
    raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")

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