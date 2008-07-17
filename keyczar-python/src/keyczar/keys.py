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

"""Represents cryptographic keys in Keyczar.

Identifies a key by its hash and type. Includes several subclasses
of base class Key.
"""

__author__ = """steveweis@gmail.com (Steve Weis), 
                arkajit.dey@gmail.com (Arkajit Dey)"""

import errors
import keyinfo
import util
import keyczar

import simplejson
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from tlslite.utils import ASN1Parser
from tlslite.utils import cryptomath

import sha
import hmac

#TODO: Note that simplejson deals in Unicode strings. So perhaps we should
#modify all Read() methods to wrap data obtained from simplejson with str().
#Currently, only problem arose with base64 conversions -- this was dealt with
#directly in the encode/decode methods. Luckily 'hello' == u'hello'.

class Key(object):
  
  """Parent class for Keyczar Keys."""
  
  def __init__(self, type, hash):
    self.type = type
    self.hash = hash
    self.__size = self.type.default_size  # initially default
    
  def __str__(self):
    return "(%s %s %s)" % (self.type, self.hash, self.key_string)
  
  def __SetSize(self, new_size):
    if self.type.IsValidSize(new_size):
      self.__size = new_size
  
  def _GetKeyString(self):
    """Return the key as a string. Abstract method."""
  
  def __GetKeyString(self):
    """Return the key as a string."""
    return self._GetKeyString()  # indirection allows subclass overriding
  
  size = property(lambda self: self.__size, __SetSize, 
                  doc="""The size of the key in bits.""")
  
  key_string = property(__GetKeyString, doc="""The key as a string.""")
  
  def Header(self):
    """Return the 6-byte header string including version, format, and hash."""
    return chr(keyczar.VERSION) + chr(keyczar.FORMAT) + util.Decode(self.hash)

class SymmetricKey(Key):
  
  """Parent class for symmetric keys such as AES, HMAC-SHA1"""
  
  def __init__(self, type, hash, key_string):
    Key.__init__(self, type, hash)
    self.__key_string = key_string
  
  def _GetKeyString(self):
    """Return the key as a string."""
    return self.__key_string

def GenKey(type, size=None):
  if size is None:
    size = type.default_size
  try:
    return {keyinfo.AES: AesKey.Generate,
            keyinfo.HMAC_SHA1: HmacKey.Generate,
            keyinfo.DSA_PRIV: DsaPrivateKey.Generate,
            keyinfo.RSA_PRIV: RsaPrivateKey.Generate}[type](size)
  except KeyError:
    if type == keyinfo.DSA_PUB or type == keyinfo.RSA_PUB:
      msg = "Public keys of type %s must be exported from private keys."
    else:
      msg = "Unsupported key type: %s"
    raise errors.KeyczarError(msg % type)

def ReadKey(type, key):
  try:
    return {keyinfo.AES: AesKey.Read,
            keyinfo.HMAC_SHA1: HmacKey.Read,
            keyinfo.DSA_PRIV: DsaPrivateKey.Read,
            keyinfo.RSA_PRIV: RsaPrivateKey.Read,
            keyinfo.DSA_PUB: DsaPublicKey.Read,
            keyinfo.RSA_PUB: RsaPublicKey.Read}[type](key)
  except KeyError:
    raise errors.KeyczarError("Unsupported key type: %s" % type)

class AesKey(SymmetricKey):
  
  def __init__(self, hash, key_string, hmac_key, size=keyinfo.AES.default_size, 
               mode=keyinfo.CBC):
    SymmetricKey.__init__(self, keyinfo.AES, hash, key_string)
    self.mode = mode
    self.hmac_key = hmac_key
    self.key_bytes = util.Decode(key_string)
    self.block_size = len(self.key_bytes)
    self.size = size
    
  def __str__(self):
    return simplejson.dumps({"type": "AES",
                             "mode": str(self.mode),
                             "hash": self.hash,
                             "aesKeyString": self.key_string,
                             "hmacKey": simplejson.loads(str(self.hmac_key))})
  
  @staticmethod
  def Generate(size=keyinfo.AES.default_size):
    """Return a newly generated AES key."""
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    hmac_key = HmacKey.Generate()  # use default HMAC-SHA1 key size
    full_hash = util.Hash([util.IntToBytes(len(key_bytes)), key_bytes, 
                           util.Decode(hmac_key.hash)])
    hash = util.Encode(full_hash[:keyczar.KEY_HASH_SIZE])
    return AesKey(hash, key_string, hmac_key, size)
  
  @staticmethod
  def Read(key):
    aes = simplejson.loads(key)
    hmac = aes['hmacKey']
    return AesKey(aes['hash'], aes['aesKeyString'], 
                  HmacKey(hmac['hash'], hmac['hmacKeyString']),
                  mode=keyinfo.GetMode(aes['mode']))
  
  def __Pad(self, data):
    """Returns the data padded using PKCS5.
    
    For a block size B and data with N bytes in the last block, PKCS5
    pads the data with B-N bytes of the value B-N.
    
    Parameters:
      data: String to be padded
    
    Returns:
      PKCS5 padded string
    """
    pad = self.block_size - len(data) % self.block_size
    return data + pad * chr(pad)
  
  def __UnPad(self, padded):
    """Returns the unpadded version of a data padded using PKCS5.
    
    Params:
      padded: String padded with PKCS5
    
    Returns:
      original, unpadded string
    """
    pad = ord(padded[-1])
    return padded[:-pad]
  
  def Encrypt(self, data):
    """Return ciphertext byte string containing Header|IV|Ciph|Sig.
    
    Parameters:
      data: String plaintext to be encrypted.
    
    Returns:
      Raw byte string ciphertext formatted to have Header|IV|Ciph|Sig.
    """
    data = self.__Pad(data)
    iv_bytes = util.RandBytes(self.block_size)
    ciph_bytes = AES.new(self.key_bytes, AES.MODE_CBC, iv_bytes).encrypt(data)
    msg_bytes = self.Header() + iv_bytes + ciph_bytes
    sig_bytes = self.hmac_key.Sign(msg_bytes)  # Sign bytes
    return msg_bytes + sig_bytes
  
  def Decrypt(self, input_bytes):
    """Decrypts the given ciphertext.
    
    Parameters:
      input_bytes: Raw byte string formatted as Header|IV|Ciph|Sig where Sig
      is the signature over the entire payload (Header|IV|Ciph).
    
    Returns:
      Plaintext String message
    
    Raises:
      ShortCiphertextError: If the ciphertext is too short to have an IV & Sig.
      InvalidSignatureError: If the signature doesn't correspond to the payload.
    """    
    data_bytes = input_bytes[keyczar.HEADER_SIZE:]  # remove header
    if len(data_bytes) < self.block_size + sha.digest_size:  # IV + sig
      raise errors.ShortCiphertextError(len(data_bytes))
    
    iv_bytes = data_bytes[:self.block_size]  # first block of bytes is the IV
    ciph_bytes = data_bytes[self.block_size:-sha.digest_size]
    sig_bytes = data_bytes[-sha.digest_size:]  # last 20 bytes are sig
    if not self.hmac_key.Verify(input_bytes[:-sha.digest_size], sig_bytes):
      raise errors.InvalidSignatureError()
    
    plain = AES.new(self.key_bytes, AES.MODE_CBC, iv_bytes).decrypt(ciph_bytes)
    return self.__UnPad(plain)
    
class HmacKey(SymmetricKey):
  
  def __init__(self, hash, key_string, size=keyinfo.HMAC_SHA1.default_size):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, hash, key_string)
    self.size = size
  
  def __str__(self):
    return simplejson.dumps({"type": "HMAC_SHA1",
                             "hash": self.hash,
                             "hmacKeyString": self.key_string})
  
  @staticmethod
  def Generate(size=keyinfo.HMAC_SHA1.default_size):
    """Return a newly generated HMAC-SHA1 key."""    
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    full_hash = util.Hash([util.IntToBytes(len(key_bytes)), key_bytes])
    hash = util.Encode(full_hash[:keyczar.KEY_HASH_SIZE])
    return HmacKey(hash, key_string, size)
  
  @staticmethod
  def Read(key):
    mac = simplejson.loads(key)
    return HmacKey(mac['hash'], mac['hmacKeyString'])
  
  def Sign(self, msg):
    """Return raw byte string of signature on the message.
    
    Parameters:
      msg: String message to be signed
    
    Returns:
      Raw byte string signature.
    """
    return hmac.new(self.key_string, msg, sha).digest()
  
  def Verify(self, msg, sig_bytes):
    """Return true if the signature corresponds to the message.
    
    Parameters:
      msg: String message that has been signed
      sig_bytes: Raw byte string of the signature.
    
    Returns:
      True if signature is valid for message. False otherwise.
    """
    return self.Sign(msg) == sig_bytes

class PrivateKey(Key):
  
  """Represents private keys in Keyczar for asymmetric key pairs."""
  
  RSA_ALG_ID = [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]
  DSA_ALG_ID = []  # TODO: Find out
  
  def __init__(self, type, hash, pkcs8, pub):
    Key.__init__(self, type, hash)
    self.pkcs8 = pkcs8
    self.public_key = pub
  
  def _GetKeyString(self):
    return self.pkcs8
  
  def _ParsePKCS8(self):
    if self.pkcs8 is None:
      return None
    byte_array = cryptomath.createByteArraySequence(util.Decode(self.pkcs8))
    parser = ASN1Parser.ASN1Parser(byte_array)
    params = None
    version = parser.getChild(0).value[0]
    if version != 0:
      raise errors.KeyczarError("Unrecognized PKCS8 Version")
    alg_id = list(parser.getChild(1).getChild(0).value)
    if alg_id != RSA_ALG_ID or alg_id != DSA_ALG_ID:
      raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")
    if alg_id == DSA_ALG_ID:
      node = parser.getChild(1).getChild(1)
      nums = [cryptomath.bytesToNumber(node.getChild(i).value) 
              for i in range(3)]
      params = {'p': nums[0], 'q': nums[1], 'g': nums[2]}
    return self._ParsePrivateKey(ASN1Parser.ASN1Parser(parser.getChild(2).value), 
                                 params)
  
  def _ParsePrivateKey(self, parser, params=None):
    """Abstract method to parse a RSA or DSA key in PrivateKey format."""

class PublicKey(Key):
  
  """Represents public keys in Keyczar for asymmetric key pairs."""
  
  def __init__(self, type, hash, x509):
    Key.__init__(self, type, hash)
    self.x509 = x509
  
  def _GetKeyString(self):
    return self.x509
  
  def _ParseX509(self):
    pass
  
  def _ParsePublicKey(self, parser):
    pass

class DsaPrivateKey(PrivateKey):
  
  @staticmethod
  def Generate(size=keyinfo.DSA_PRIV.default_size):
    """Return a newly generated DSA private key."""
  
  @staticmethod
  def Read(key):
    pass

class RsaPrivateKey(PrivateKey):
  
  def __init__(self, hash, pkcs8, pub, key, size=keyinfo.RSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.RSA_PRIV, hash, pkcs8, pub)
    self.params = self._ParsePKCS8()
    self.key = key  # instance of PyCrypto RSA key
    self.size = size
  
  def _ParsePrivateKey(self, parser, params=None):
    version = parser.getChild(0).value[0]
    nums = [cryptomath.bytesToNumber(parser.getChild(i).value) 
              for i in range(1,9)]
    return {'n': nums[0], 'e': nums[1], 'd': nums[2], 'p': nums[3], 
            'q': nums[4], 'dp': nums[5], 'dq': nums[6], 'qinv': nums[7]}
  
  @staticmethod
  def Generate(size=keyinfo.RSA_PRIV.default_size):
    """Return a newly generated RSA private key."""
    key_pair = RSA.generate(size, util.RandBytes)
    pub_key = key_pair.publickey()
    pub = RsaPublicKey('HashAB', None, pub_key, size)  
    # FIXME: need hash, x509 data
    return RsaPrivateKey(pub.hash, None, pub, key_pair, size) 
    # FIXME: need a way to import/export to pkcs8
  
  @staticmethod
  def Read(key):
    rsa = simplejson.loads(key)
    pub_key = rsa['publicKey']
    pub = RsaPublicKey(pub_key['hash'], pub_key['x509'], None) # FIXME: get key
    rsa_key = RsaPrivateKey(rsa['hash'], rsa['pkcs8'], pub)
  
  def Encrypt(self, data):
    """Return ciphertext byte string containing Header|Ciphertext
    
    Parameters:
      data: String plaintext to be encrypted.
    
    Returns:
      Raw byte string ciphertext formatted to have Header|Ciphertext
    """
    ciph_bytes = self.key.encrypt(data, None)[0]  # PyCrypto returns 1-tuple
    return self.Header() + ciph_bytes
  
  def Decrypt(self, input_bytes):
    """Decrypts the given ciphertext.
    
    Parameters:
      input_bytes: Raw byte string formatted as Header|Ciphertext.
    
    Returns:
      Plaintext String message
    """
    ciph_bytes = input_bytes[keyczar.HEADER_SIZE:]
    return self.key.decrypt(ciph_bytes)
  
  def Sign(self, msg):
    """Return raw byte string of signature on the message.
    
    Parameters:
      msg: String message to be signed
    
    Returns:
      Long int signature.
    """
    return self.key.sign(msg, None)[0]
  
  def Verify(self, msg, sig):
    """Return true if the signature corresponds to the message.
    
    Parameters:
      msg: String message that has been signed
      sig: Long int signature.
    
    Returns:
      True if signature is valid for message. False otherwise.
    """
    return sig == self.Sign(msg)

class DsaPublicKey(PublicKey):
  
  @staticmethod
  def Read(key):
    pass

class RsaPublicKey(PublicKey):
  
  def __init__(self, hash, x509, key, size=keyinfo.RSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.RSA_PUB, hash, x509)
    self.params = self._ParseX509()
    self.key = key
    self.size = size
  
  @staticmethod
  def Read(key):
    rsa = simplejson.loads(key)
    # parse pyrcrypto rsa public key from x509
    return RsaPublicKey(rsa['hash'], rsa['x509'], None)