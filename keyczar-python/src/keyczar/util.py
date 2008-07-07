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

from Crypto.Util.randpool import RandomPool
import sha

def IntToBytes(n):
  """Return byte string of 4 big-endian ordered bytes representing n."""
  bytes = [m % 256 for m in [n >> 24, n >> 16, n >> 8, n]]
  return "".join([chr(b) for b in bytes])  # byte array to byte string

def RandBytes(n):
  rp = RandomPool(256)
  return rp.getBytes(n)

def Hash(inputs):
  md = sha.new()
  for i in inputs:
    md.update(i)
  return md.digest()