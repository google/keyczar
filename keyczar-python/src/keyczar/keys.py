#!/usr/bin/python2.4
#
# Copyright 2008 Google Inc.
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

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import hmac
import math
import random
import sha

from Crypto.Cipher import AES
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
import simplejson

import errors
import keyczar
import keyinfo
import util

#TODO: Note that simplejson deals in Unicode strings. So perhaps we should
#modify all Read() methods to wrap data obtained from simplejson with str().
#Currently, only problem arose with base64 conversions -- this was dealt with
#directly in the encode/decode methods. Luckily 'hello' == u'hello'.

def GenKey(type, size=None):
  """
  Generates a key of the given type and length.
  
  @param type: the type of key to generate
  @type type: L{keyinfo.KeyType}
  
  @param size: the length in bits of the key to be generated
  @type size: integer
  
  @return: the generated key of the given type and size
  
  @raise KeyczarError: if type is a public key or unsupported.
  """
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
  """
  Reads a key of the given type from a JSON string representation.
  
  @param type: the type of key to read
  @type type: L{keyinfo.KeyType}
  
  @param key: the JSON string representation of the key
  @type key: string
  
  @return: the key object read from the JSON string
  
  @raise KeyczarError: if type is unsupported
  """
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
    """Indirect getter for the key string."""
    return self._GetKeyString()
  
  def _Hash(self):
    """Compute and return the hash id of this key. Can override default hash."""
    fullhash = util.Hash(util.IntToBytes(len(self.key_bytes)), self.key_bytes)
    return util.Encode(fullhash[:keyczar.KEY_HASH_SIZE])
  
  def __Hash(self):
    """Indirect getter for hash."""
    return self._Hash()
  
  hash = property(__Hash, doc="""The hash id of the key.""")
  size = property(lambda self: self.__size, __SetSize, 
                  doc="""The size of the key in bits.""")
  key_string = property(__GetKeyString, doc="""The key as a Base64 string.""")
  key_bytes = property(lambda self: util.Decode(self.key_string), 
                       doc="""The key as bytes.""")
  
  def Header(self):
    """Return the 5-byte header string including version byte, 4-byte hash."""
    return chr(keyczar.VERSION) + util.Decode(self.hash)

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
    self._params = params

class AesKey(SymmetricKey):
  """Represents AES symmetric private keys."""
  
  def __init__(self, key_string, hmac_key, size=keyinfo.AES.default_size, 
               mode=keyinfo.CBC):
    SymmetricKey.__init__(self, keyinfo.AES, key_string)
    self.hmac_key = hmac_key
    self.block_size = len(self.key_bytes)
    self.size = size
    self.mode = mode    

  def __str__(self):
    return simplejson.dumps({"mode": str(self.mode),
                             "size": self.size,
                             "aesKeyString": self.key_string,
                             "hmacKey": simplejson.loads(str(self.hmac_key))})

  def _Hash(self):
    fullhash = util.Hash(util.IntToBytes(len(self.key_bytes)), self.key_bytes, 
                         util.IntToBytes(keyczar.KEY_HASH_SIZE), 
                         util.Decode(self.hmac_key.hash))
    return util.Encode(fullhash[:keyczar.KEY_HASH_SIZE])

  @staticmethod
  def Generate(size=keyinfo.AES.default_size):
    """
    Return a newly generated AES key.
    
    @param size: length of key in bits to generate
    @type size: integer
    
    @return: an AES key
    @rtype: L{AesKey}
    """
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    hmac_key = HmacKey.Generate()  # use default HMAC-SHA1 key size
    return AesKey(key_string, hmac_key, size)
  
  @staticmethod
  def Read(key):
    """
    Reads an AES key from a JSON string representation of it.
    
    @param key: a JSON representation of an AES key
    @type key: string
    
    @return: an AES key
    @rtype: L{AesKey}
    """
    aes = simplejson.loads(key)
    hmac = aes['hmacKey']
    return AesKey(aes['aesKeyString'], 
                  HmacKey(hmac['hmacKeyString'], hmac['size']), 
                  aes['size'], keyinfo.GetMode(aes['mode']))
  
  def __Pad(self, data):
    """
    Returns the data padded using PKCS5.
    
    For a block size B and data with N bytes in the last block, PKCS5
    pads the data with B-N bytes of the value B-N.
    
    @param data: data to be padded
    @type data: string
    
    @return: PKCS5 padded string
    @rtype: string
    """
    pad = self.block_size - len(data) % self.block_size
    return data + pad * chr(pad)
  
  def __UnPad(self, padded):
    """
    Returns the unpadded version of a data padded using PKCS5.
    
    @param padded: string padded with PKCS5
    @type padded: string
    
    @return: original, unpadded string
    @rtype: string
    """
    pad = ord(padded[-1])
    return padded[:-pad]
  
  def Encrypt(self, data):
    """
    Return ciphertext byte string containing Header|IV|Ciph|Sig.
    
    @param data: plaintext to be encrypted.
    @type data: string
    
    @return: raw byte string ciphertext formatted to have Header|IV|Ciph|Sig.
    @rtype: string
    """
    data = self.__Pad(data)
    iv_bytes = util.RandBytes(self.block_size)
    ciph_bytes = AES.new(self.key_bytes, AES.MODE_CBC, iv_bytes).encrypt(data)
    msg_bytes = self.Header() + iv_bytes + ciph_bytes
    sig_bytes = self.hmac_key.Sign(msg_bytes)  # Sign bytes
    return msg_bytes + sig_bytes
  
  def Decrypt(self, input_bytes):
    """
    Decrypts the given ciphertext.
    
    @param input_bytes: raw byte string formatted as Header|IV|Ciph|Sig where 
      Sig is the signature over the entire payload (Header|IV|Ciph).
    @type input_bytes: string
    
    @return: plaintext message
    @rtype: string
    
    @raise ShortCiphertextError: if the ciphertext is too short to have IV & Sig
    @raise InvalidSignatureError: if the signature doesn't correspond to payload
    """    
    data_bytes = input_bytes[keyczar.HEADER_SIZE:]  # remove header
    if len(data_bytes) < self.block_size + util.HLEN:  # IV + sig
      raise errors.ShortCiphertextError(len(data_bytes))
    
    iv_bytes = data_bytes[:self.block_size]  # first block of bytes is the IV
    ciph_bytes = data_bytes[self.block_size:-util.HLEN]
    sig_bytes = data_bytes[-util.HLEN:]  # last 20 bytes are sig
    if not self.hmac_key.Verify(input_bytes[:-util.HLEN], sig_bytes):
      raise errors.InvalidSignatureError()
    
    plain = AES.new(self.key_bytes, AES.MODE_CBC, iv_bytes).decrypt(ciph_bytes)
    return self.__UnPad(plain)
    
class HmacKey(SymmetricKey):
  """Represents HMAC-SHA1 symmetric private keys."""
  
  def __init__(self, key_string, size=keyinfo.HMAC_SHA1.default_size):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, key_string)
    self.size = size
  
  def __str__(self):
    return simplejson.dumps({"size": self.size, 
                             "hmacKeyString": self.key_string})
  
  @staticmethod
  def Generate(size=keyinfo.HMAC_SHA1.default_size):
    """
    Return a newly generated HMAC-SHA1 key.
    
    @param size: length of key in bits to generate
    @type size: integer
    
    @return: an HMAC-SHA1 key
    @rtype: L{HmacKey}
    """
    key_bytes = util.RandBytes(size / 8)
    key_string = util.Encode(key_bytes)
    return HmacKey(key_string, size)
  
  @staticmethod
  def Read(key):
    """
    Reads an HMAC-SHA1 key from a JSON string representation of it.
    
    @param key: a JSON representation of an HMAC-SHA1 key
    @type key: string
    
    @return: an HMAC-SHA1 key
    @rtype: L{HmacKey}
    """    
    mac = simplejson.loads(key)
    return HmacKey(mac['hmacKeyString'], mac['size'])
  
  def Sign(self, msg):
    """
    Return raw byte string of signature on the message.
    
    @param msg: message to be signed
    @type msg: string
    
    @return: raw byte string signature
    @rtype: string
    """
    return hmac.new(self.key_bytes, msg, sha).digest()
  
  def Verify(self, msg, sig_bytes):
    """
    Return True if the signature corresponds to the message.
    
    @param msg: message that has been signed
    @type msg: string
    
    @param sig_bytes: raw byte string of the signature
    @type sig_bytes: string
    
    @return: True if signature is valid for message. False otherwise.
    @rtype: boolean
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
                             "pkcs8": self.pkcs8, 
                             "size": self.size})

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
    return simplejson.dumps({"x509": self.x509, "size": self.size})
  
  def _GetKeyString(self):
    return self.x509

class DsaPrivateKey(PrivateKey):  
  """Represents DSA private keys in an asymmetric DSA key pair."""
  
  def __init__(self, params, pkcs8, pub, key, 
               size=keyinfo.DSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.DSA_PRIV, params, pkcs8, pub)
    self.key = key
    self.size = size
  
  @staticmethod
  def Generate(size=keyinfo.DSA_PRIV.default_size):
    """
    Return a newly generated DSA private key.
    
    @param size: length of key in bits to generate
    @type size: integer
    
    @return: a DSA private key
    @rtype: L{DsaPrivateKey}
    """
    key = DSA.generate(size, util.RandBytes)
    params = {'g': key.g, 'p': key.p, 'q': key.q, 'y': key.y, 'x': key.x}
    pubkey = key.publickey()
    pub_params = {'g': pubkey.g, 'p': pubkey.p, 'q': pubkey.q, 'y': pubkey.y}
    pub = DsaPublicKey(pub_params, util.ExportDsaX509(pub_params), pubkey, size)
    return DsaPrivateKey(params, util.ExportDsaPkcs8(params), pub, key, size)
  
  @staticmethod
  def Read(key):
    """
    Reads a DSA private key from a JSON string representation of it.
    
    @param key: a JSON representation of a DSA private key
    @type key: string
    
    @return: an DSA private key
    @rtype: L{DsaPrivateKey}
    """
    dsa = simplejson.loads(key)
    pub = DsaPublicKey.Read(simplejson.dumps(dsa['publicKey']))
    params = util.ParsePkcs8(dsa['pkcs8'])
    key = DSA.construct((pub._params['y'], params['g'], params['p'], params['q'], 
                         params['x']))
    return DsaPrivateKey(params, dsa['pkcs8'], pub, key, dsa['size'])
  
  def Sign(self, msg):
    """
    Return raw byte string of signature on the message.
    
    @param msg: message to be signed
    @type msg: string
    
    @return: byte string formatted as an ASN.1 sequnce of r and s
    @rtype: string 
    """
    k = random.randint(2, self.key.q-1)  # need to chose a random k per-message
    (r, s) = self.key.sign(util.Hash(msg), k)
    return util.MakeDsaSig(r, s)
  
  def Verify(self, msg, sig):
    """@see: L{DsaPublicKey.Verify}"""
    return self.public_key.Verify(msg, sig)

class RsaPrivateKey(PrivateKey):
  """Represents RSA private keys in an asymmetric RSA key pair."""
  
  def __init__(self, params, pkcs8, pub, key, 
               size=keyinfo.RSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.RSA_PRIV, params, pkcs8, pub)
    self.key = key  # instance of PyCrypto RSA key
    self.size = size
    
  def __Decode(self, em, p=""):
    if len(p) >= 2**61 or len(em) < 2 * util.HLEN + 2:  
      # 2^61 = the input limit for SHA-1
      raise errors.KeyczarError("OAEP Decoding Error")
    # PyCrypto strips all leading zeros, can't check it
    masked_seed = em[:util.HLEN]
    masked_db = em[util.HLEN:]
    seed_mask = util.MGF(masked_db, util.HLEN)
    seed = util.Xor(masked_seed, seed_mask)
    db_mask = util.MGF(seed, len(em) - util.HLEN)  # em already stripped of 0
    db = util.Xor(masked_db, db_mask)
    ph = db[:util.HLEN]
    one = db.find(chr(1), util.HLEN)
    if ph != util.Hash(p) or one == -1:
      raise errors.KeyczarError("OAEP Decoding Error")
    return db[one+1:]  # the message
  
  @staticmethod
  def Generate(size=keyinfo.RSA_PRIV.default_size):
    """
    Return a newly generated RSA private key.
    
    @param size: length of key in bits to generate
    @type size: integer
    
    @return: a RSA private key
    @rtype: L{RsaPrivateKey}
    """
    key = RSA.generate(size, util.RandBytes)
    params = {'n': key.n, 'e': key.e, 'd': key.d, 'p': key.q, 'q': key.p,  
              'dp': key.d % (key.q - 1), 'dq': key.d % (key.p - 1), 
              'invq': key.u}
    #NOTE: PyCrypto stores p < q, u = p^{-1} mod q
    #But OpenSSL and PKCS8 stores q < p, invq = q^{-1} mod p
    #So we have to reverse the p and q values
    pubkey = key.publickey()
    pub_params = {'n': pubkey.n, 'e': pubkey.e}
    pub = RsaPublicKey(pub_params, util.ExportRsaX509(pub_params), pubkey, size)
    return RsaPrivateKey(params, util.ExportRsaPkcs8(params), pub, key, size)
  
  @staticmethod
  def Read(key):
    """
    Reads a RSA private key from a JSON string representation of it.
    
    @param key: a JSON representation of a RSA private key
    @type key: string
    
    @return: a RSA private key
    @rtype: L{RsaPrivateKey}
    """
    rsa = simplejson.loads(key)
    pub = RsaPublicKey.Read(simplejson.dumps(rsa['publicKey']))
    params = util.ParsePkcs8(rsa['pkcs8'])
    key = RSA.construct((params['n'], params['e'], params['d'],
                         params['q'], params['p'], params['invq']))
    return RsaPrivateKey(params, rsa['pkcs8'], pub, key, rsa['size'])
  
  def Encrypt(self, data):
    """@see: L{RsaPublicKey.Encrypt}"""
    return self.public_key.Encrypt(data)
  
  def Decrypt(self, input_bytes):
    """
    Decrypts the given ciphertext.
    
    @param input_bytes: raw byte string formatted as Header|Ciphertext.
    @type input_bytes: string
    
    @return: plaintext message
    @rtype: string
    """
    ciph_bytes = input_bytes[keyczar.HEADER_SIZE:]
    decrypted = self.key.decrypt(ciph_bytes)
    return self.__Decode(decrypted)
  
  def Sign(self, msg):
    """
    Return raw byte string of signature on the SHA-1 hash of the message.
    
    @param msg: message to be signed
    @type msg: string
    
    @return: string representation of long int signature over message
    @rtype: string
    """
    emsa_encoded = util.MakeEmsaMessage(msg, self.size)
    return util.BigIntToBytes(self.key.sign(emsa_encoded, None)[0])
  
  def Verify(self, msg, sig):
    """@see: L{RsaPublicKey.Verify}"""
    return self.public_key.Verify(msg, sig)

class DsaPublicKey(PublicKey):
  
  """Represents DSA public keys in an asymmetric DSA key pair."""
  
  def __init__(self, params, x509, key, size=keyinfo.DSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.DSA_PUB, params, x509)
    self.key = key
    self.size = size
  
  @staticmethod
  def Read(key):
    """
    Reads a DSA public key from a JSON string representation of it.
    
    @param key: a JSON representation of a DSA public key
    @type key: string
    
    @return: a DSA public key
    @rtype: L{DsaPublicKey}
    """
    dsa = simplejson.loads(key)
    params = util.ParseX509(dsa['x509'])
    pubkey = DSA.construct((params['y'], params['g'], params['p'], params['q']))
    return DsaPublicKey(params, dsa['x509'], pubkey, dsa['size'])
  
  def Verify(self, msg, sig):
    """
    Return True if the signature corresponds to the message.
    
    @param msg: message that has been signed
    @type msg: string
    
    @param sig: raw byte string of the signature formatted as an ASN.1 sequence
      of r and s
    @type sig: string
    
    @return: True if signature is valid for message. False otherwise.
    @rtype: boolean
    """
    try:
      (r, s) = util.ParseDsaSig(sig)
      return self.key.verify(util.Hash(msg), (r, s))
    except errors.KeyczarError:
      # if signature is not in correct format
      return False

class RsaPublicKey(PublicKey):
  """Represents RSA public keys in an asymmetric RSA key pair."""
  
  def __init__(self, params, x509, key, size=keyinfo.RSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.RSA_PUB, params, x509)
    self.key = key
    self.size = size
  
  def __Encode(self, msg, p=""):
    if len(p) >= 2**61:  # the input limit for SHA-1
      raise errors.KeyczarError("OAEP parameter string too long.")
    k = int(math.floor(math.log(self._params['n'], 256)) + 1) # num bytes in n
    if len(msg) > k - 2 * util.HLEN - 2:
      raise errors.KeyczarError("Message too long to OAEP encode.")
    ph = util.Hash(p)
    ps = (k - len(msg) - 2 * util.HLEN - 2) * chr(0)  # zero byte string
    db = "".join([ph, ps, chr(1), msg])
    seed = util.RandBytes(util.HLEN)
    db_mask = util.MGF(seed, k - util.HLEN - 1)
    masked_db = util.Xor(db, db_mask)
    seed_mask = util.MGF(masked_db, util.HLEN)
    masked_seed = util.Xor(seed, seed_mask)
    return "".join([chr(0), masked_seed, masked_db])
  
  @staticmethod
  def Read(key):
    """
    Reads a RSA public key from a JSON string representation of it.
    
    @param key: a JSON representation of a RSA public key
    @type key: string
    
    @return: a RSA public key
    @rtype: L{RsaPublicKey}
    """
    rsa = simplejson.loads(key)
    params = util.ParseX509(rsa['x509'])
    pubkey = RSA.construct((params['n'], params['e']))
    return RsaPublicKey(params, rsa['x509'], pubkey, rsa['size'])
  
  def Encrypt(self, data):
    """
    Return a raw byte string of the ciphertext in the form Header|Ciph.
    
    @param data: message to be encrypted
    @type data: string
    
    @return: ciphertext formatted as Header|Ciph
    @rtype: string 
    """
    data = self.__Encode(data)
    ciph_bytes = self.key.encrypt(data, None)[0]  # PyCrypto returns 1-tuple
    return self.Header() + ciph_bytes
  
  def Verify(self, msg, sig):
    """
    Return True if the signature corresponds to the message.
    
    @param msg: message that has been signed
    @type msg: string
    
    @param sig: string representation of long int signature
    @type sig: string
    
    @return: True if signature is valid for the message hash. False otherwise.
    @rtype: boolean
    """
    try:
      return self.key.verify(util.MakeEmsaMessage(msg, self.size), (util.BytesToInt(sig),))
    except ValueError:
      # if sig is not a long, it's invalid
      return False