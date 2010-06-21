#!/usr/bin/env python
"""
Convert C++ generated keyset to Java compatible keyset.

Keysets generated with Keyczar C++ < Revision 466 produced RSA and DSA
keys incompatibles with Keyczar Java implementation. This script can be
used to convert its old keysets and make them compatible with all three
implementations (C++, Java, Python).

Usage: ./convert_keyset.py src_keyset dst_keyset

src_keyset: keyset to convert
dst_keyset: destination directory (should be empty)
"""
import base64
import os
import sys
try:
  import simplejson as json
except ImportError:
  import json

FIELDS = [
    # RSA fields
    "crtCoefficient",
    "primeExponentP",
    "primeExponentQ",
    "primeP",
    "primeQ",
    "privateExponent",
    "modulus",
    "publicExponent",
    # DSA fields
    "g",
    "p",
    "q",
    "y",
    "x",
    ]

def read_file(path):
    fo = file(path, 'rb')
    content = ''
    try:
        content = fo.read()
    finally:
        fo.close()
    return content

def write_file(path, data):
    fo = file(path, 'wb')
    try:
        fo.write(data)
    finally:
        fo.close()

def b64_decode(s):
    # Copied from keyczar/util.py
    s = str(s.replace(" ", ""))
    d = len(s) % 4
    if d == 1:
        raise ValueError
    elif d == 2:
        s += "=="
    elif d == 3:
        s += "="
    return base64.urlsafe_b64decode(s)

def b64_encode(s):
    # Copied from keyczar/util.py
    return base64.urlsafe_b64encode(str(s)).replace("=", "")

def rewrite_inplace_rec(d):
    for field in d:
        if isinstance(d[field], dict):
            rewrite_inplace_rec(d[field])
        if field not in FIELDS:
            continue
        d[field] = b64_encode('\x00' + b64_decode(d[field]))

def rewrite_key(src_path, dst_path, version):
    orig_json = read_file(os.path.join(src_path, str(version)))
    key = json.loads(orig_json)
    rewrite_inplace_rec(key)
    new_json = json.dumps(key)
    write_file(os.path.join(dst_path, str(version)), new_json)

def iterate_meta(src_path, dst_path):
    json_string = read_file(os.path.join(src_path, 'meta'))
    meta = json.loads(json_string)
    versions = meta["versions"]
    for version in versions:
        rewrite_key(src_path, dst_path, version["versionNumber"])
    write_file(os.path.join(dst_path, 'meta'), json_string)

def doit(src_path, dst_path):
    for p in (src_path, dst_path):
        if not os.path.isdir(p):
            sys.stderr.write('Invalid directory: %s\n' % p)
            return
    iterate_meta(src_path, dst_path)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.stderr.write('./convert_keyset.py src_keyset dst_keyset\n')
    doit(sys.argv[1], sys.argv[2])
