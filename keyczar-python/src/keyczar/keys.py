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
from Crypto.Util import number

import sha
import hmac

#TODO: Note that simplejson deals in Unicode strings. So perhaps we should
#modify all Read() methods to wrap data obtained from simplejson with str().
#Currently, only problem arose with base64 conversions -- this was dealt with
#directly in the encode/decode methods. Luckily 'hello' == u'hello'.

#TODO: Should JSON of key files (not meta files) store KeyType or not?
#Inconsistencies across the files. Decide on a standard.

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

class Key(object):
  
  """Parent class for Keyczar Keys."""
  
  def __init__(self, type):
    self.type = type
    self.__size = self.type.default_size  # initially default
  
  def __SetSize(self, new_size):
    if self.type.IsValidSize(new_size):
      self.__size = new_size
  
  def _GetKeyString(self):
    """Return the key as a string. Abstract method."""
  
  def __GetKeyString(self):
    """Return the key as a string."""
    return self._GetKeyString()  # indirection allows subclass overriding
  
  def _Hash(self):
    """Compute and return the hash id of this key. Can override default hash."""
    fullhash = util.Hash([util.IntToBytes(len(self.key_bytes)), self.key_bytes])
    return util.Encode(fullhash[:keyczar.KEY_HASH_SIZE])
  
  def __Hash(self):
    return self._Hash()  # indirection allows subclass overriding
  
  hash = property(__Hash, doc="""The hash id of the key.""")
  size = property(lambda self: self.__size, __SetSize, 
                  doc="""The size of the key in bits.""")
  key_string = property(__GetKeyString, doc="""The key as a Base64 string.""")
  key_bytes = property(lambda self: util.Decode(self.key_string), 
                       doc="""The key as bytes.""")
  
  def Header(self):
    """Return the 6-byte header string including version, format, and hash."""
    return chr(keyczar.VERSION) + chr(keyczar.FORMAT) + util.Decode(self.hash)

class SymmetricKey(Key):
  
  """Parent class for symmetric keys such as AES, HMAC-SHA1"""
  
  def __init__(self, type, key_string):
    Key.__init__(self, type)
    self.__key_string = key_string
  
  def _GetKeyString(self):
    """Return the key as a string."""
    return self.__key_string

class AsymmetricKey(Key):
  
  """Parent class for asymmetric keys."""
  
  def __init__(self, type, params):
    Key.__init__(self, type)
    self.__params = params

class AesKey(SymmetricKey):
  
  def __init__(self, key_string, hmac_key, size=keyinfo.AES.default_size, 
               mode=keyinfo.CBC):
    SymmetricKey.__init__(self, keyinfo.AES, key_string)
    self.hmac_key = hmac_key
    self.block_size = len(self.key_bytes)
    self.size = size
    self.mode = mode    
    
  def __str__(self):
    return simplejson.dumps({"type": "AES",
                             "mode": str(self.mode),
                             "aesKeyString": self.key_string,
                             "hmacKey": simplejson.loads(str(self.hmac_key))})
    
  def _Hash(self):
    fullhash = util.Hash([util.IntToBytes(len(self.key_bytes)), self.key_bytes, 
                          util.Decode(self.hmac_key.hash)])
    return util.Encode(fullhash[:keyczar.KEY_HASH_SIZE])
  
  @staticmethod
  def Generate(size=keyinfo.AES.default_size):
    """Return a newly generated AES key."""
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    hmac_key = HmacKey.Generate()  # use default HMAC-SHA1 key size
    return AesKey(key_string, hmac_key, size)
  
  @staticmethod
  def Read(key):
    aes = simplejson.loads(key)
    hmac = aes['hmacKey']
    return AesKey(aes['aesKeyString'], HmacKey(hmac['hmacKeyString']),
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
  
  def __init__(self, key_string, size=keyinfo.HMAC_SHA1.default_size):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, key_string)
    self.size = size
  
  def __str__(self):
    return simplejson.dumps({"type": "HMAC_SHA1",
                             "hmacKeyString": self.key_string})
  
  @staticmethod
  def Generate(size=keyinfo.HMAC_SHA1.default_size):
    """Return a newly generated HMAC-SHA1 key."""    
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    return HmacKey(key_string, size)
  
  @staticmethod
  def Read(key):
    mac = simplejson.loads(key)
    return HmacKey(mac['hmacKeyString'])
  
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

class PrivateKey(AsymmetricKey):
  
  """Represents private keys in Keyczar for asymmetric key pairs."""
  
  def __init__(self, type, params, pkcs8, pub):
    AsymmetricKey.__init__(self, type, params)
    self.pkcs8 = pkcs8
    self.public_key = pub
  
  def __str__(self):
    return simplejson.dumps({"publicKey": simplejson.loads(
                                                          str(self.public_key)),
                             "type": str(self.type),
                             "pkcs8": self.pkcs8})
  
  def _GetKeyString(self):
    return self.pkcs8
  
  def _Hash(self):
    return self.public_key.hash

class PublicKey(AsymmetricKey):
  
  """Represents public keys in Keyczar for asymmetric key pairs."""
  
  def __init__(self, type, params, x509):
    AsymmetricKey.__init__(self, type, params)
    self.x509 = x509
  
  def __str__(self):
    return simplejson.dumps({"type": str(self.type),
                             "x509": self.x509})
  
  def _GetKeyString(self):
    return self.x509

class DsaPrivateKey(PrivateKey):
  
  @staticmethod
  def Generate(size=keyinfo.DSA_PRIV.default_size):
    """Return a newly generated DSA private key."""
  
  @staticmethod
  def Read(key):
    pass

class RsaPrivateKey(PrivateKey):
  
  def __init__(self, params, pkcs8, pub, key, 
               size=keyinfo.RSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.RSA_PRIV, params, pkcs8, pub)
    self.key = key  # instance of PyCrypto RSA key
    self.size = size
  
  @staticmethod
  def Generate(size=keyinfo.RSA_PRIV.default_size):
    """Return a newly generated RSA private key."""
    key = RSA.generate(size, util.RandBytes)
    params = {'n': key.n, 'e': key.e, 'd': key.d, 'p': key.q, 'q': key.p,  
              'dp': key.d % key.q, 'dq': key.d % key.p, 'invq': key.u}
    #NOTE: PyCrypto stores p < q, u = p^{-1} mod q
    #But OpenSSL and PKCS8 stores q < p, invq = q^{-1} mod p
    #So we have to reverse the p and q values
    pubkey = key.publickey()
    pub_params = {'n': pubkey.n, 'e': pubkey.e}
    x509 = util.Decode(util.ExportRsaX509(pub_params))
    pub = RsaPublicKey(pub_params, util.Encode(x509), pubkey, size)
    return RsaPrivateKey(params, util.ExportRsaPkcs8(params), pub, key, size)
  
  @staticmethod
  def Read(key):
    rsa = simplejson.loads(key)
    pubkey = rsa['publicKey']
    pub_params = util.ParseX509(pubkey['x509'])
    pycrypt_pub = RSA.construct((pub_params['n'], pub_params['e']))
    pub = RsaPublicKey(pub_params, pubkey['x509'], pycrypt_pub)
    params = util.ParsePkcs8(rsa['pkcs8'])
    key = RSA.construct((params['n'], params['e'], params['d'],
                         params['q'], params['p'], params['invq']))
    return RsaPrivateKey(params, rsa['pkcs8'], pub, key)
  
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
      String representation of long int signature.
    """
    return str(self.key.sign(msg, None)[0])
  
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
  
  def __init__(self, params, x509, key, size=keyinfo.RSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.RSA_PUB, params, x509)
    self.key = key
    self.size = size
  
  @staticmethod
  def Read(key):
    rsa = simplejson.loads(key)
    params = util.ParseX509(rsa['x509'])
    pubkey = RSA.construct((params['n'], params['e']))
    return RsaPublicKey(params, rsa['x509'], pubkey)