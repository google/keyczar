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

from Crypto.Util.randpool import RandomPool
import sha
import base64

def IntToBytes(n):
  """Return byte string of 4 big-endian ordered bytes representing n."""
  bytes = [m % 256 for m in [n >> 24, n >> 16, n >> 8, n]]
  return "".join([chr(b) for b in bytes])  # byte array to byte string

def RandBytes(n):
  """Return n random bytes."""
  rp = RandomPool(256)
  return rp.get_bytes(n)

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
    