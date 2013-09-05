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

Identifies a key by its hash_id and type. Includes several subclasses
of base class Key.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import hmac
import math
import random
try:
  # Import hashlib if Python >= 2.5
  from hashlib import sha1
except ImportError:
  import sha as sha1

from Crypto.Cipher import AES
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
try:
  import simplejson as json
except ImportError:
  import json

# do we have access to M2Crypto?
try:
    from M2Crypto import EVP
except ImportError:
    EVP = None

# overideable crypt library selection
ACTIVE_CRYPT_LIB = 'm2crypto' if EVP else 'pycrypto'

import errors
import keyczar
import keyinfo
import util

#TODO: Note that simplejson deals in Unicode strings. So perhaps we should
#modify all Read() methods to wrap data obtained from simplejson with str().
#Currently, only problem arose with base64 conversions -- this was dealt with
#directly in the encode/decode methods. Luckily 'hello' == u'hello'.

def GenKey(key_type, size=None):
  """
  Generates a key of the given key_type and length.

  @param key_type: the key_type of key to generate
  @key_type key_type: L{keyinfo.KeyType}

  @param size: the length in bits of the key to be generated
  @key_type size: integer

  @return: the generated key of the given key_type and size

  @raise KeyczarError: if key_type is a public key or unsupported or if key size
                       is unsupported.
  """
  if size is None:
    size = key_type.default_size

  if not key_type.IsValidSize(size):
    raise errors.KeyczarError("Unsupported key size %d bits." % size)

  try:
    return {keyinfo.AES: AesKey.Generate,
            keyinfo.HMAC_SHA1: HmacKey.Generate,
            keyinfo.DSA_PRIV: DsaPrivateKey.Generate,
            keyinfo.RSA_PRIV: RsaPrivateKey.Generate}[key_type](size)
  except KeyError:
    if key_type == keyinfo.DSA_PUB or key_type == keyinfo.RSA_PUB:
      msg = "Public keys of key_type %s must be exported from private keys."
    else:
      msg = "Unsupported key key_type: %s"
    raise errors.KeyczarError(msg % key_type)

def ReadKey(key_type, key):
  """
  Reads a key of the given key_type from a JSON string representation.

  @param key_type: the key_type of key to read
  @key_type key_type: L{keyinfo.KeyType}

  @param key: the JSON string representation of the key
  @key_type key: string

  @return: the key object read from the JSON string

  @raise KeyczarError: if key_type is unsupported
  """
  try:
    return {keyinfo.AES: AesKey.Read,
            keyinfo.HMAC_SHA1: HmacKey.Read,
            keyinfo.DSA_PRIV: DsaPrivateKey.Read,
            keyinfo.RSA_PRIV: RsaPrivateKey.Read,
            keyinfo.DSA_PUB: DsaPublicKey.Read,
            keyinfo.RSA_PUB: RsaPublicKey.Read}[key_type](key)
  except KeyError:
    raise errors.KeyczarError("Unsupported key key_type: %s" % key_type)

class Key(object):

  """Parent class for Keyczar Keys."""

  def __init__(self, key_type):
    self.type = key_type
    self.__size = self.type.default_size  # initially default

  def __eq__(self, other):
    return (self.type == other.type and
            self.size == other.size and
            self.key_string == other.key_string)

  def __SetSize(self, new_size):
    if self.type.IsValidSize(new_size):
      self.__size = new_size

  def _GetKeyString(self):
    """Return the key as a string. Abstract method."""

  def __GetKeyString(self):
    """Indirect getter for the key string."""
    return self._GetKeyString()

  def _Hash(self):
    """Compute and return the hash_id id of this key. Can override default hash_id."""
    fullhash = util.Hash(util.IntToBytes(len(self.key_bytes)), self.key_bytes)
    return util.Base64WSEncode(fullhash[:keyczar.KEY_HASH_SIZE])

  def __Hash(self):
    """Indirect getter for hash_id."""
    return self._Hash()

  hash_id = property(__Hash, doc="""The hash_id id of the key.""")
  size = property(lambda self: self.__size, __SetSize,
                  doc="""The size of the key in bits.""")
  key_string = property(__GetKeyString, doc="""The key as a Base64 string.""")
  key_bytes = property(lambda self: util.Base64WSDecode(self.key_string),
                       doc="""The key as bytes.""")

  def Header(self):
    """Return the 5-byte header string including version byte, 4-byte hash_id."""
    return chr(keyczar.VERSION) + util.Base64WSDecode(self.hash_id)

class SymmetricKey(Key):
  """Parent class for symmetric keys such as AES, HMAC-SHA1"""

  def __init__(self, key_type, key_string):
    Key.__init__(self, key_type)
    self.__key_string = key_string

  def _GetKeyString(self):
    """Return the key as a string."""
    return self.__key_string

class AsymmetricKey(Key):
  """Parent class for asymmetric keys."""

  def __init__(self, key_type, params):
    Key.__init__(self, key_type)
    self._params = params

class AesKey(SymmetricKey):
  """Represents AES symmetric private keys."""

  class AESAdaptor(object):

    """
    Adaptor class to make PyCrypto's Cipher behave the same as M2Crypto's
    EVP.Cipher class
    """

    def __init__(self, key_bytes, iv_bytes, mode):
      """
      Constructor

      @param key_bytes: the key for this cipher
      @type key: string

      @param iv_bytes: the initialization vector for this cipher
      @type iv_bytes: string

      @param mode: the cipher mode
      @type mode: integer (using AES values, e.g. AES.MODE_CBC)
      """
      self.cipher = AES.new(key_bytes, mode, iv_bytes)

    def __getattr__(self, name):
      # defer everything to the actual cipher instance
      return getattr(self.cipher, name)

    def final(self):
      """
      Collect any remaining encrypted data i.e. non-block size conforming

      @return: remaining encrypted data, if any
      """
      # except 'final' which is a no-op
      return ''

  class EVPAdaptor(object):

    """
    Adaptor class to make M2Crypto's EVP.Cipher behave the same as PyCrypto's
    Cipher class
    """

    # cipher selection mode - EVP needs a different cipher for each
    OP_ACTIVE = -1 # indicator that the request is for an existing cipher
    OP_DECRYPT = 0
    OP_ENCRYPT = 1
    OP_TYPES = (OP_ACTIVE, OP_DECRYPT, OP_ENCRYPT)

    def __init__(self, key_bytes, iv_bytes, mode):
      """
      Constructor

      @param key_bytes: the key for this cipher
      @type key: string

      @param iv_bytes: the initialization vector for this cipher
      @type iv_bytes: string

      @param mode: the cipher mode
      @type mode: integer (using AES values, e.g. AES.MODE_CBC)
      """
      # defer construction of ciphers until encrypt/decrypt request made
      self.ciphers = {}
      # preserve the data needed for cipher construction
      self.key_bytes = key_bytes
      self.IV = iv_bytes
      self.mode = mode
      self.block_size = AES.block_size
      self.key_size = len(key_bytes)

    def __Cipher(self, selector):
      """
      Helper to get the cipher for this adaptor, creates if required

      @param selector: type of cipher required (active/encrypt/decrypt)
      @type selector: integer one of OP_TYPES

      @return: EVP.Cipher
      """
      assert selector in self.OP_TYPES, 'Invalid selector :%s' %selector
      if selector == self.OP_ACTIVE and (len(self.ciphers.keys()) > 1 or 
                                         not len(self.ciphers.keys())):
        assert 0, 'If both encryption and decryption used then selector must \
            be OP_ENCRYPT or OP_DECRYPT and at least 1 must be active'

      cipher = None
      if selector == self.OP_ACTIVE:
        # should only be one cipher active
        cipher = self.ciphers.values()[0]
      else:
        cipher = self.ciphers.get(selector)
        # have we been created a cipher for this selector yet?
        if not cipher:
          # no, so set it up as requested

          # convert between AES and EVP modes
          # NOTE: AES auto-selects based on key size using the same mode, but
          # EVP requires different mode strings for each key size (in bits)
          mode = 'aes_%s_cbc' %(self.key_size*8)
          cipher = EVP.Cipher(alg=mode,
                              key=self.key_bytes, 
                              iv=self.IV,
                              op=selector,
                              padding=0
                             )
          self.ciphers[selector] = cipher
      return cipher

    def decrypt(self, string):
      """
      Return decrypted byte string

      @param string: bytes to be decrypted.
      @type string: string

      @return: plaintext string
      @rtype: string
      """
      return self.__Cipher(self.OP_DECRYPT).update(string)

    def encrypt(self, string):
      """
      Return encrypted byte string

      @param string: plaintext to be encrypted.
      @type string: string

      @return: raw byte encrypted string  
      @rtype: string
      """
      return self.__Cipher(self.OP_ENCRYPT).update(string)

    def final(self, selector=OP_ACTIVE):
      """
      Collect any remaining encrypted data i.e. non-block size conforming

      @return: remaining encrypted data, if any
      """
      return self.__Cipher(selector).final()

  def __init__(self, key_string, hmac_key, size=keyinfo.AES.default_size,
               mode=keyinfo.CBC):
    SymmetricKey.__init__(self, keyinfo.AES, key_string)
    self.hmac_key = hmac_key
    # sanity check in case other code was dependant on this specific value,
    # prior to it being changed to AES.block_size
    assert AES.block_size == 16
    self.block_size = AES.block_size
    self.size = size
    # Only CBC mode is actually supported, in spite of what the signature leads you to believe.
    assert mode == keyinfo.CBC

  def __str__(self):
    return json.dumps({"mode": str(keyinfo.CBC),
                       "size": self.size,
                       "aesKeyString": self.key_string,
                       "hmacKey": json.loads(str(self.hmac_key))})

  def _Hash(self):
    fullhash = util.Hash(util.IntToBytes(len(self.key_bytes)),
                         self.key_bytes,
                         self.hmac_key.key_bytes)
    return util.Base64WSEncode(fullhash[:keyczar.KEY_HASH_SIZE])

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
    key_string = util.Base64WSEncode(key_bytes)
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
    aes = json.loads(key)
    hmac_val = aes['hmacKey']
    return AesKey(aes['aesKeyString'],
                  HmacKey(hmac_val['hmacKeyString'], hmac_val['size']),
                  aes['size'], keyinfo.GetMode(aes['mode']))

  def _Pad(self, data):
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

  def _UnPad(self, padded):
    """
    Returns the unpadded version of a data padded using PKCS5.

    @param padded: string padded with PKCS5
    @type padded: string

    @return: original, unpadded string
    @rtype: string
    """
    pad = ord(padded[-1])
    return padded[:-pad]

  def _NoPadBufferSize(self, buffer_size):
    """
    Return a buffer size that does not require padding that is closest to the
    requested buffer size. Minimum size is 1 block.

    Returns a multiple of the cipher block size so there is NO PADDING required 
    on any blocks of this size

    @param buffer_size: requested buffer size
    @type data: int

    @return: best buffer size
    @rtype: int
    """
    no_pad_size = self.block_size * (buffer_size / self.block_size)
    return max(no_pad_size, self.block_size)

  def Encrypt(self, data):
    """
    Return ciphertext byte string containing Header|IV|Ciph|Sig.

    @param data: plaintext to be encrypted.
    @type data: string

    @return: raw byte string ciphertext formatted to have Header|IV|Ciph|Sig.
    @rtype: string
    """
    data = self._Pad(data)
    iv_bytes = util.RandBytes(self.block_size)
    cipher = self.__CreateCipher(self.key_bytes, iv_bytes)
    ciph_bytes = cipher.encrypt(data)
    ciph_bytes += cipher.final()
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
    return self._UnPad(plain)

  def __CreateCipher(self, key_bytes, iv_bytes, mode=AES.MODE_CBC):
    """
    Factory function for creating cipher of specified type using the active
    crypto library

    @param key_bytes: the key for this cipher
    @type key: string

    @param iv_bytes: the initialization vector for this cipher
    @type iv_bytes: string

    @param mode: the cipher mode
    @type mode: integer (using AES values, e.g. AES.MODE_CBC)

    @return: the cipher object
    """
    # can we use M2Crypto and was it requested?
    if ACTIVE_CRYPT_LIB.lower() == 'm2crypto' and EVP:
      # yes, so do so
      return self.EVPAdaptor(key_bytes, iv_bytes, mode)
    else:
      # default to PyCrypto
      return self.AESAdaptor(key_bytes, iv_bytes, mode)

class HmacKey(SymmetricKey):
  """Represents HMAC-SHA1 symmetric private keys."""

  def __init__(self, key_string, size=keyinfo.HMAC_SHA1.default_size):
    SymmetricKey.__init__(self, keyinfo.HMAC_SHA1, key_string)
    self.size = size

  def __str__(self):
    return json.dumps({"size": self.size, "hmacKeyString": self.key_string})

  def _Hash(self):
    fullhash = util.Hash(self.key_bytes)
    return util.Base64WSEncode(fullhash[:keyczar.KEY_HASH_SIZE])

  def CreateStreamable(self):
      """Return a streaming version of this key"""
      return HmacKeyStream(self)

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
    key_string = util.Base64WSEncode(key_bytes)
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
    mac = json.loads(key)
    return HmacKey(mac['hmacKeyString'], mac['size'])

  def Sign(self, msg):
    """
    Return raw byte string of signature on the message.

    @param msg: message to be signed
    @type msg: string

    @return: raw byte string signature
    @rtype: string
    """
    return hmac.new(self.key_bytes, msg, sha1).digest()

  def Verify(self, msg, sig_bytes):
    """
    Return True if the signature corresponds to the message.

    @param msg: message to be signed
    @type msg: string

    @param sig_bytes: raw byte string of the signature
    @type sig_bytes: string

    @return: True if signature is valid for message. False otherwise.
    @rtype: boolean
    """
    return self.VerifySignedData(self.Sign(msg), sig_bytes)

  def VerifySignedData(self, mac_bytes, sig_bytes):
    """
    Return True if the signature corresponds to the signed message

    @param msg: message that has been signed
    @type msg: string

    @param sig_bytes: raw byte string of the signature
    @type sig_bytes: string

    @return: True if signature is valid for message. False otherwise.
    @rtype: boolean
    """
    if len(sig_bytes) != len(mac_bytes):
      return False
    result = 0
    for x, y in zip(mac_bytes, sig_bytes):
      result |= ord(x) ^ ord(y)
    return result == 0

class HmacKeyStream(object):
  """Represents streamable HMAC-SHA1 symmetric private keys."""

  def __init__(self, hmac_key):
    self.hmac_key = hmac_key
    self.hmac = hmac.new(self.hmac_key.key_bytes, '', sha1)

  def Update(self, data):
      self.hmac.update(data)

  def Sign(self):
    """
    Return raw byte string of signature on the streamed message.

    @return: raw byte string signature
    @rtype: string
    """
    return self.hmac.digest()


class PrivateKey(AsymmetricKey):
  """Represents private keys in Keyczar for asymmetric key pairs."""

  def __init__(self, key_type, params, pub):
    AsymmetricKey.__init__(self, key_type, params)
    self.public_key = pub

  def _Hash(self):
    return self.public_key.hash_id

class PublicKey(AsymmetricKey):
  """Represents public keys in Keyczar for asymmetric key pairs."""

  def __init__(self, key_type, params):
    AsymmetricKey.__init__(self, key_type, params)

class DsaPrivateKey(PrivateKey):
  """Represents DSA private keys in an asymmetric DSA key pair."""

  def __init__(self, params, pub, key,
               size=keyinfo.DSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.DSA_PRIV, params, pub)
    self.key = key
    self.public_key = pub
    self.params = params
    self.size = size

  def __str__(self):
    return json.dumps({"publicKey": json.loads(str(self.public_key)),
                       "x": util.Base64WSEncode(self.params['x']),
                       "size": self.size})

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
    params = { 'x': util.PadBytes(util.BigIntToBytes(key.x), 1) }
    pubkey = key.publickey()
    pub_params = { 'g': util.PadBytes(util.BigIntToBytes(pubkey.g), 1),
                   'p': util.PadBytes(util.BigIntToBytes(pubkey.p), 1),
                   'q': util.PadBytes(util.BigIntToBytes(pubkey.q), 1),
                   'y': util.PadBytes(util.BigIntToBytes(pubkey.y), 1)
                   }
    pub = DsaPublicKey(pub_params, pubkey, size)
    return DsaPrivateKey(params, pub, key, size)

  @staticmethod
  def Read(key):
    """
    Reads a DSA private key from a JSON string representation of it.

    @param key: a JSON representation of a DSA private key
    @type key: string

    @return: an DSA private key
    @rtype: L{DsaPrivateKey}
    """
    dsa = json.loads(key)
    pub = DsaPublicKey.Read(json.dumps(dsa['publicKey']))
    params = { 'x' : util.Base64WSDecode(dsa['x']) }
    key = DSA.construct((util.BytesToLong(pub._params['y']),
                         util.BytesToLong(pub._params['g']),
                         util.BytesToLong(pub._params['p']),
                         util.BytesToLong(pub._params['q']),
                         util.BytesToLong(params['x'])))
    return DsaPrivateKey(params, pub, key, dsa['size'])

  def Sign(self, msg):
    """
    Return raw byte string of signature on the message.

    @param msg: message to be signed
    @type msg: string

    @return: byte string formatted as an ASN.1 sequnce of r and s
    @rtype: string
    """
    # Need to chose a random k per-message, SystemRandom() is available
    # since Python 2.4.
    k = random.SystemRandom().randint(2, self.key.q-1)
    (r, s) = self.key.sign(util.Hash(msg), k)
    return util.MakeDsaSig(r, s)

  def Verify(self, msg, sig):
    """@see: L{DsaPublicKey.Verify}"""
    return self.public_key.Verify(msg, sig)

class RsaPrivateKey(PrivateKey):
  """Represents RSA private keys in an asymmetric RSA key pair."""

  def __init__(self, params, pub, key, size=keyinfo.RSA_PRIV.default_size):
    PrivateKey.__init__(self, keyinfo.RSA_PRIV, params, pub)
    self.key = key  # instance of PyCrypto RSA key
    self.public_key = pub  # instance of Keyczar RsaPublicKey
    self.params = params
    self.size = size

  # em - encoded message
  def __Decode(self, encoded_message, label=""):
    # See PKCS#1 v2.1: ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
    if len(label) >= 2**61:
      # 2^61 = the input limit for SHA-1
      raise errors.KeyczarError("OAEP Decoding Error - label is too large %d" % len(label))
    if len(encoded_message) < 2 * util.HLEN + 2:
      raise errors.KeyczarError(
        "OAEP Decoding Error - encoded_message is too small: %d" % len(encoded_message))

    # Step 3b  EM = Y || maskedSeed || maskedDB
    k = int(math.floor(math.log(self.key.n, 256)) + 1) # num bytes in n
    diff_len = k - len(encoded_message)
    # PyCrypto strips out leading zero bytes.
    # In OAEP, the first byte is expected to be a zero, so we can ignore it
    if diff_len > 1:
      # If more bytes were chopped by PyCrypto, add zero bytes back on
      encoded_message = '\x00' * (diff_len - 1) + encoded_message

    masked_seed = encoded_message[:util.HLEN]
    masked_datablock = encoded_message[util.HLEN:]

    # Step 3c,d
    seed_mask = util.MGF(masked_datablock, util.HLEN)
    seed = util.Xor(masked_seed, seed_mask)

    # Step 3e
    datablock_mask = util.MGF(seed, len(masked_datablock))  # encoded_message already stripped of 0

    # Step 3f
    datablock = util.Xor(masked_datablock, datablock_mask)

    label_hash = datablock[:util.HLEN]
    expected_label_hash = util.Hash(label)  # Debugging
    if label_hash != expected_label_hash:
      raise errors.KeyczarError("OAEP Decoding Error - hash_id is invalid")

    delimited_message = datablock[util.HLEN:].lstrip('\x00')
    if delimited_message[0] != '\x01':
      raise errors.KeyczarError("OAEP Decoding Error - expected a 1 value")
    return delimited_message[1:]  # The message

  def __str__(self):
    return json.dumps({ 
      "publicKey": json.loads(str(self.public_key)),
      "privateExponent": util.Base64WSEncode(self.params['privateExponent']),
      "primeP": util.Base64WSEncode(self.params['primeP']),
      "primeQ": util.Base64WSEncode(self.params['primeQ']),
      "primeExponentP": util.Base64WSEncode(self.params['primeExponentP']),
      "primeExponentQ": util.Base64WSEncode(self.params['primeExponentQ']),
      "crtCoefficient": util.Base64WSEncode(self.params['crtCoefficient']),
      "size": self.size})

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
    #NOTE: PyCrypto stores p < q, u = p^{-1} mod q
    #But OpenSSL and PKCS8 stores q < p, invq = q^{-1} mod p
    #So we have to reverse the p and q values
    params = { 'privateExponent': util.PadBytes(util.BigIntToBytes(key.d), 1),
               'primeP': util.PadBytes(util.BigIntToBytes(key.q), 1),
               'primeQ': util.PadBytes(util.BigIntToBytes(key.p), 1),
               'primeExponentP': util.PadBytes(util.BigIntToBytes(key.d % (key.q - 1)), 1),
               'primeExponentQ': util.PadBytes(util.BigIntToBytes(key.d % (key.p - 1)), 1),
               'crtCoefficient': util.PadBytes(util.BigIntToBytes(key.u), 1)}
    pubkey = key.publickey()
    pub_params = { 'modulus': util.PadBytes(util.BigIntToBytes(key.n), 1),
                   'publicExponent': util.PadBytes(util.BigIntToBytes(key.e), 1)}
    pub = RsaPublicKey(pub_params, pubkey, size)
    return RsaPrivateKey(params, pub, key, size)

  @staticmethod
  def Read(key):
    """
    Reads a RSA private key from a JSON string representation of it.

    @param key: a JSON representation of a RSA private key
    @type key: string

    @return: a RSA private key
    @rtype: L{RsaPrivateKey}
    """
    rsa = json.loads(key)
    pub = RsaPublicKey.Read(json.dumps(rsa['publicKey']))
    params = {'privateExponent': util.Base64WSDecode(rsa['privateExponent']),
              'primeP': util.Base64WSDecode(rsa['primeP']),
              'primeQ': util.Base64WSDecode(rsa['primeQ']),
              'primeExponentP': util.Base64WSDecode(rsa['primeExponentP']),
              'primeExponentQ': util.Base64WSDecode(rsa['primeExponentQ']),
              'crtCoefficient': util.Base64WSDecode(rsa['crtCoefficient'])
              }

    key = RSA.construct((util.BytesToLong(pub.params['modulus']),
                         util.BytesToLong(pub.params['publicExponent']),
                         util.BytesToLong(params['privateExponent']),
                         util.BytesToLong(params['primeQ']),
                         util.BytesToLong(params['primeP']),
                         util.BytesToLong(params['crtCoefficient'])))
    return RsaPrivateKey(params, pub, key, rsa['size'])

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
    Return raw byte string of signature on the SHA-1 hash_id of the message.

    @param msg: message to be signed
    @type msg: string

    @return: string representation of long int signature over message
    @rtype: string
    """
    emsa_encoded = util.MakeEmsaMessage(msg, self.size)
    byte_string = util.BigIntToBytes(self.key.sign(emsa_encoded, None)[0])
    return util.PadBytes(byte_string, self.size/8 - len(byte_string))

  def Verify(self, msg, sig):
    """@see: L{RsaPublicKey.Verify}"""
    return self.public_key.Verify(msg, sig)

class DsaPublicKey(PublicKey):

  """Represents DSA public keys in an asymmetric DSA key pair."""

  def __init__(self, params, key, size=keyinfo.DSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.DSA_PUB, params)
    self.key = key
    self.params = params
    self.size = size

  def __str__(self):
    return json.dumps({"p": util.Base64WSEncode(self.params['p']),
                       "q": util.Base64WSEncode(self.params['q']),
                       "g": util.Base64WSEncode(self.params['g']),
                       "y": util.Base64WSEncode(self.params['y']),
                       "size": self.size})

  def _Hash(self):
    fullhash = util.PrefixHash(util.TrimBytes(self._params['p']),
                         util.TrimBytes(self._params['q']),
                         util.TrimBytes(self._params['g']),
                         util.TrimBytes(self._params['y']))
    return util.Base64WSEncode(fullhash[:keyczar.KEY_HASH_SIZE])

  @staticmethod
  def Read(key):
    """
    Reads a DSA public key from a JSON string representation of it.

    @param key: a JSON representation of a DSA public key
    @type key: string

    @return: a DSA public key
    @rtype: L{DsaPublicKey}
    """

    dsa = json.loads(key)
    params = {'y': util.Base64WSDecode(dsa['y']),
              'p': util.Base64WSDecode(dsa['p']),
              'g': util.Base64WSDecode(dsa['g']),
              'q': util.Base64WSDecode(dsa['q'])}
    pubkey = DSA.construct((util.BytesToLong(params['y']),
                            util.BytesToLong(params['g']),
                            util.BytesToLong(params['p']),
                            util.BytesToLong(params['q'])))
    return DsaPublicKey(params, pubkey, dsa['size'])

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

  def __init__(self, params, key, size=keyinfo.RSA_PUB.default_size):
    PublicKey.__init__(self, keyinfo.RSA_PUB, params)
    self.key = key
    self.params = params
    self.size = size

  def __Encode(self, msg, label=""):
    if len(label) >= 2**61:  # the input limit for SHA-1
      raise errors.KeyczarError("OAEP parameter string too long.")
    k = int(math.floor(math.log(self.key.n, 256)) + 1) # num bytes in n
    if len(msg) > k - 2 * util.HLEN - 2:
      raise errors.KeyczarError("Message too long to OAEP encode.")
    label_hash = util.Hash(label)
    pad_octets = (k - len(msg) - 2 * util.HLEN - 2)  # Number of zeros to pad
    if pad_octets < 0:
      raise errors.KeyczarError("Message is too long: %d" % len(msg))
    datablock = label_hash + ('\x00' * pad_octets) + '\x01' + msg
    seed = util.RandBytes(util.HLEN)

    # Steps 2e, f
    datablock_mask = util.MGF(seed, k - util.HLEN - 1)
    masked_datablock = util.Xor(datablock, datablock_mask)

    # Steps 2g, h
    seed_mask = util.MGF(masked_datablock, util.HLEN)
    masked_seed = util.Xor(seed, seed_mask)

    # Step 2i: Construct the encoded message
    return '\x00' + masked_seed + masked_datablock

  def __str__(self):
    return json.dumps(
      {"modulus": util.Base64WSEncode(self.params['modulus']),
       "publicExponent": util.Base64WSEncode(self.params['publicExponent']),
       "size": self.size})

  def _Hash(self):
    fullhash = util.PrefixHash(util.TrimBytes(self._params['modulus']),
                               util.TrimBytes(self._params['publicExponent']))
    return util.Base64WSEncode(fullhash[:keyczar.KEY_HASH_SIZE])

  @staticmethod
  def Read(key):
    """
    Reads a RSA public key from a JSON string representation of it.

    @param key: a JSON representation of a RSA public key
    @type key: string

    @return: a RSA public key
    @rtype: L{RsaPublicKey}
    """
    rsa = json.loads(key)
    params = {'modulus': util.Base64WSDecode(rsa['modulus']),
              'publicExponent': util.Base64WSDecode(rsa['publicExponent'])}

    pubkey = RSA.construct((util.BytesToLong(params['modulus']),
                            util.BytesToLong(params['publicExponent'])))
    return RsaPublicKey(params, pubkey, rsa['size'])

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

    @return: True if signature is valid for the message hash_id. False otherwise.
    @rtype: boolean
    """
    try:
      return self.key.verify(util.MakeEmsaMessage(msg, self.size), (util.BytesToLong(sig),))
    except ValueError:
      # if sig is not a long, it's invalid
      return False

class EncryptingStreamWriter(object):
  """
  An encrypting stream capable of creating a ciphertext byte stream
  containing Header|IV|Ciph|Sig.
  """

  def __init__(self, key, output_stream):
    """
    Constructor

    @param key: Keyczar Key to perform the padding, verification, cipher
    creation needed by this stream
    @type key: Key

    @param output_stream: stream for encrypted output
    @type output_stream: 'file-like' object
    """
    self.__key = key
    self.__output_stream = output_stream
    self.__data = ''
    self.__closed = False

    self.__hmac_stream = key.hmac_key.CreateStreamable()
    iv_bytes = util.RandBytes(key.block_size)
    self.__cipher = AES.new(key.key_bytes, AES.MODE_CBC, iv_bytes)

    hdr = key.Header()
    self.__hmac_stream.Update(hdr + iv_bytes)
    self.__output_stream.write(hdr + iv_bytes)

  def write(self, data):
    """
    Write the data in encrypted form to the output stream

    @param data: data to be encrypted.
    @type data: string
    """
    self.__CheckOpen('write')
    self.__data += data
    encrypt_buffer_size = self.__key._NoPadBufferSize(len(self.__data))

    if len(self.__data) >= encrypt_buffer_size:
      self.__WriteEncrypted(self.__data[:encrypt_buffer_size])
    else:
      encrypt_buffer_size = 0

    self.__data = self.__data[encrypt_buffer_size:]

  def flush(self):
    """
    Flush this stream. 
    Writes all remaining encrypted data to the output stream.
    Will also flush the associated output stream.
    """
    self.__CheckOpen('flush')
    self.__WriteEncrypted(self.__data, pad=True)
    self.__output_stream.write(self.__hmac_stream.Sign())
    self.__output_stream.flush()

  def close(self):
    """
    Close this stream. 
    Discards any and all buffered data
    Does *not* close the associated output stream.
    """
    self.__CheckOpen('close')
    self.__closed = True

  def __WriteEncrypted(self, data, pad=False):
    """
    Helper to write encrypted bytes to output stream.
    Must *only* pad the last block as PKCS5 *always* pads, even when the data
    length is a multiple of the block size - it adds block_size chars.
    We cannot pad intermediate blocks as there is no guarantee that a streaming
    read will receive the data in the same blocks as the writes were made.

    @param data: data to be written.
    @type data: string

    @param pad: add padding to data
    @type pad: boolean
    """
    if pad:
      data = self.__key._Pad(data)

    encrypted_bytes = self.__cipher.encrypt(data)
    self.__output_stream.write(encrypted_bytes)
    self.__hmac_stream.Update(encrypted_bytes)

  def __CheckOpen(self, operation):
    """Helper to ensure this stream is open"""
    if self.__closed:
      raise ValueError('%s() on a closed stream is not permitted' %operation)

class DecryptingStreamReader(object):
  """
  A stream capable of decrypting a source ciphertext byte stream
  containing Header|IV|Ciph|Sig into plain text.
  """

  def __init__(self, key_set, input_stream,
               buffer_size=util.DEFAULT_STREAM_BUFF_SIZE):
    """
    Constructor

    @param key_set: Keyczar key set to source key specified in message header
    @type key: Keyczar

    @param input_stream: source of encrypted input
    @type input_stream: 'file-like' object

    @param buffer_size: Suggested buffer size for reading data (will be 
    adjusted to suit the underlying cipher). 
    Use -1 to read as much data as possible from the source stream
    @type buffer_size: integer
    """
    self.__key_set = key_set
    self.__input_stream = input_stream
    self.__buffer_size = buffer_size
    self.__key = None
    self.__cipher = None
    self.__encrypted_buffer = ''
    self.__decrypted_buffer = ''
    self.__closed = False

  def read(self, chars=-1):
    """ 
    Decrypts data from the source stream and returns the resulting plaintext.
    NOTE: the signature validation is performed on the final read if sufficient
    data is available. Streaming => it isn't possible to validate up front as
    done by Decrypt().

    @param chars: indicates the number of characters to read from the stream.
    read() will never return more than chars characters, but it might return
    less, if there are not enough characters available.
    @type chars: integer

    @raise ShortCiphertextError: if the ciphertext is too short to have IV & Sig
    @raise InvalidSignatureError: if the signature doesn't correspond to payload
    @raise KeyNotFoundError: if key specified in header doesn't exist
    @raise ValueError: if stream closed
    """
    self.__CheckOpen('read')
    is_data_avail = True
    if not self.__key:
      is_data_avail = self.__CreateKey()

    if is_data_avail and self.__key and not self.__cipher:
      is_data_avail = self.__CreateCipher()

    if is_data_avail and self.__key and self.__cipher:
      data_to_decrypt = ''
      need_more_data = True
      while need_more_data:
        read_bytes, is_data_avail = self.__ReadBytes(self.__key.block_size,
                                                     block=False)
        if read_bytes:
          self.__encrypted_buffer += read_bytes

        reserved_data_len = util.HLEN
        if is_data_avail:
          reserved_data_len += self.__key.block_size

        available_data = self.__encrypted_buffer[:-reserved_data_len]

        if is_data_avail:
          no_decrypt_len = len(available_data) % self.__key.block_size
        else:
          no_decrypt_len = 0
        # slicing with [:-0] does not work!
        if no_decrypt_len:
          data_to_decrypt = available_data[:-no_decrypt_len]
        else:
          data_to_decrypt = available_data

        need_more_data = (is_data_avail and not data_to_decrypt)

      if data_to_decrypt:
        self.__hmac_stream.Update(data_to_decrypt)
        self.__encrypted_buffer = self.__encrypted_buffer[len(data_to_decrypt):]
        decrypted_data = self.__cipher.decrypt(data_to_decrypt)
        
        if not is_data_avail:
          if len(self.__encrypted_buffer) != util.HLEN:
            raise errors.ShortCiphertextError(len(self.__encrypted_buffer))
          current_sig_bytes = self.__hmac_stream.Sign()
          msg_sig_bytes = self.__encrypted_buffer
          self.__encrypted_buffer = ''
          if not self.__key.hmac_key.VerifySignedData(current_sig_bytes, 
                                                      msg_sig_bytes):
            raise errors.InvalidSignatureError()
          decrypted_data = self.__key._UnPad(decrypted_data)
          
        self.__decrypted_buffer += decrypted_data
        
    if chars < 0:
      result = self.__decrypted_buffer
      self.__decrypted_buffer = ''
    else:
      result = self.__decrypted_buffer[:chars]
      self.__decrypted_buffer = self.__decrypted_buffer[chars:]

    if not result and is_data_avail:
      result = None

    return result

  def close(self):
    """
    Close this stream. 
    Assumes all data has been read or is thrown away as no signature validation
    is done until all the data is read.
    """
    self.__closed = True

  def __CheckOpen(self, operation):
    """Helper to ensure this stream is open"""
    if self.__closed:
      raise ValueError('%s() on a closed stream is not permitted' %operation)

  def __ReadBytes(self, size, block=True):
    """
    Helper to read bytes from the input stream. If requested will block until
    required number of bytes is read or input data is exhausted.  Returns a
    tuple of (the data bytes read, is more data available).
    """
    need_more_data = True
    result = ''
    while need_more_data:
      read_bytes = self.__input_stream.read(size)
      if read_bytes:
        result += read_bytes
      elif read_bytes is not None:
        return (result, False)
      elif not block:
        return (result, True)
      need_more_data = (len(result) < size)

    return (result, True)

  def __CreateKey(self):
    """
    Helper to create the actual key from the Header
    NOTE: The key determines what the optimal read buffer size will be. It is a
    size that does not require any padding to allow allow encrypting without
    using a stream anddecrypting with a stream 
    i.e. Encrypt() => DecryptingStreamReader()
    """
    is_data_avail = True
    if not self.__key:
      read_bytes, is_data_avail = self.__ReadBytes(keyczar.HEADER_SIZE -
                                                   len(self.__encrypted_buffer))
      if read_bytes:
        self.__encrypted_buffer += read_bytes

      if len(self.__encrypted_buffer) >= keyczar.HEADER_SIZE:
        hdr_bytes = self.__encrypted_buffer[:keyczar.HEADER_SIZE]
        self.__encrypted_buffer = self.__encrypted_buffer[keyczar.HEADER_SIZE:]
        self.__key = self.__key_set._ParseHeader(hdr_bytes)
        self.__hmac_stream = self.__key.hmac_key.CreateStreamable()
        self.__hmac_stream.Update(hdr_bytes)
        if self.__buffer_size >= 0:
          self.__buffer_size = self.__key._NoPadBufferSize(self.__buffer_size)

    return is_data_avail

  def __CreateCipher(self):
    """
    Helper to create the cipher using the IV from the message
    """
    is_data_avail = True
    if not self.__cipher:
      reqd_block_size = self.__key.block_size
      new_bytes_reqd = reqd_block_size - len(self.__encrypted_buffer)
      read_bytes, is_data_avail = self.__ReadBytes(new_bytes_reqd)
      if read_bytes:
        self.__encrypted_buffer += read_bytes
      if len(self.__encrypted_buffer) >= reqd_block_size:
        iv_bytes = self.__encrypted_buffer[:reqd_block_size]
        self.__encrypted_buffer = self.__encrypted_buffer[
            reqd_block_size:]
        self.__hmac_stream.Update(iv_bytes)
        self.__cipher = AES.new(self.__key.key_bytes, AES.MODE_CBC, iv_bytes)
    return is_data_avail

