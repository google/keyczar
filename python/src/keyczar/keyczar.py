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

"""
Collection of all Keyczar classes used to perform cryptographic functions:
encrypt, decrypt, sign and verify.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import os
import warnings

import errors
import json
import keydata
import keyinfo
import keys
import readers
import writers
import util

VERSION = 0
VERSION_BYTE = '\x00'
KEY_HASH_SIZE = 4
HEADER_SIZE = 1 + KEY_HASH_SIZE

class Keyczar(object):
  """Abstract Keyczar base class."""

  __metaclass__ = util.ABCMeta

  def __init__(self, reader):
    self.metadata = keydata.KeyMetadata.Read(reader.GetMetadata())
    self._keys = {}  # maps both KeyVersions and hash ids to keys
    self.primary_version = None  # default if no primary key
    self.default_size = self.metadata.type.default_size

    if not self.IsAcceptablePurpose(self.metadata.purpose):
      raise errors.KeyczarError("Unacceptable purpose: %s"
                                % self.metadata.purpose)

    if self.metadata.encrypted and not isinstance(reader,
                                                  readers.EncryptedReader):
      raise errors.KeyczarError("Need encrypted reader.")

    for version in self.metadata.versions:
      if version.status == keyinfo.PRIMARY:
        if self.primary_version is not None:
          raise errors.KeyczarError(
              "Key sets may only have a single primary version")
        self.primary_version = version
      key = keys.ReadKey(self.metadata.type,
                         reader.GetKey(version.version_number))
      self._keys[version] = key
      self._keys[key.hash_id] = key

  versions = property(lambda self: [k for k in self._keys.keys()
                                    if isinstance(k, keydata.KeyVersion)],
                      doc="""List of versions in key set.""")
  primary_key = property(lambda self: self.GetKey(self.primary_version),
                         doc="""The primary key for this key set.""")

  def __str__(self):
    return str(self.metadata)

  def _ParseHeader(self, header):
    """
    Parse the header and verify version, format info. Return key if exists.

    @param header: the bytes of the header of Keyczar output
    @type header: string

    @return: the key identified by the hash in the header
    @rtype: L{keys.Key}

    @raise BadVersionError: if header specifies an illegal version
    @raise KeyNotFoundError: if key specified in header doesn't exist
    """
    version = ord(header[0])
    if version != VERSION:
      raise errors.BadVersionError(version)
    return self.GetKey(util.Base64WSEncode(header[1:]))

  @staticmethod
  def Read(location):
    """
    Return a Keyczar object created from FileReader at given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Keyczar to manage the keys stored at the given location
    @rtype: L{Keyczar}
    """
    return Keyczar(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Indicates whether purpose is valid. Abstract method."""

  def GetKey(self, key_id):
    """
    Returns the key associated with the given key_id, a hash or a version.

    @param key_id: Either the hash identifier of the key or its version.
    @type key_id: string or L{keydata.KeyVersion}

    @return: key associated with this key_id or None if key_id doesn't exist.
    @rtype: L{keys.Key}

    @raise KeyNotFoundError: if key with given key_id doesn't exist
    """
    try:
      return self._keys[key_id]
    except KeyError:
      raise errors.KeyNotFoundError(key_id)

  def _AddKey(self, version, key):
    self._keys[version] = self._keys[key.hash_id] = key
    self.metadata.AddVersion(version)

class GenericKeyczar(Keyczar):

  """To be used by Keyczart."""

  @staticmethod
  def Read(location):
    """Return a GenericKeyczar created from FileReader at given location."""
    return GenericKeyczar(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """All purposes ok for Keyczart."""
    return True

  def AddVersion(self, status, size=None):
    """
    Adds a new key version with given status to key set.

    Generates a new key of same type (repeated until hash identifier is unique)
    for this version. Uses supplied key size (if provided) in lieu of the
    default key size. If this is an unacceptable key size, raises an error. Uses
    next available version number.

    @param status: the status of the new key to be added
    @type status: L{keyinfo.KeyStatus}

    @param size: size of key in bits, uses default size if not provided.
    @type size: integer

    @raise KeyczarError: if either key type or key size is unsupported.
    """
    if size is None:
      size = self.default_size

    if not self.metadata.type.IsValidSize(size):
      raise errors.KeyczarError("Unsupported key size %d bits." % size)

    max_version_number = 0
    for version in self.versions:
      if max_version_number < version.version_number:
        max_version_number = version.version_number

    # Make the new version number the max of the existing versions plus one
    version = keydata.KeyVersion(max_version_number + 1, status, False)

    if status == keyinfo.PRIMARY:
      if self.primary_version is not None:
        self.primary_version.status = keyinfo.ACTIVE
      self.primary_version = version

    if size < self.default_size:
      print("WARNING: %d-bit key size is less than recommended default key"
            "size of %d bits for %s keys."
            % (size, self.default_size, str(self.metadata.type)))

    # Make sure no keys collide on their identifiers
    while True:
      key = keys.GenKey(self.metadata.type, size)
      if self._keys.get(key.hash_id) is None:
        break

    self._AddKey(version, key)

  def Promote(self, version_number):
    """
    Promotes the status of key with given version number.

    Promoting ACTIVE key automatically demotes current PRIMARY key to ACTIVE.

    @param version_number: the version number to promote
    @type version_number: integer

    @raise KeyczarError: if invalid version number or trying to promote
      a primary key
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.PRIMARY:
      raise errors.KeyczarError("Can't promote a primary key.")
    elif version.status == keyinfo.ACTIVE:
      version.status = keyinfo.PRIMARY
      if self.primary_version is not None:
        self.primary_version.status = keyinfo.ACTIVE  # only one primary key
      self.primary_version = version
    elif version.status == keyinfo.INACTIVE:
      version.status = keyinfo.ACTIVE

  def Demote(self, version_number):
    """
    Demotes the status of key with given version number.

    Demoting PRIMARY key results in a key set with no primary version.

    @param version_number: the version number to demote
    @type version_number: integer

    @raise KeyczarError: if invalid version number or trying to demote an
    inactive key, use L{Revoke} instead.
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.PRIMARY:
      version.status = keyinfo.ACTIVE
      self.primary_version = None  # no more primary keys in the set
    elif version.status == keyinfo.ACTIVE:
      version.status = keyinfo.INACTIVE
    elif version.status == keyinfo.INACTIVE:
      raise errors.KeyczarError("Can't demote an inactive key, only revoke.")

  def Revoke(self, version_number):
    """
    Revokes the key with given version number if scheduled to be revoked.

    @param version_number: integer version number to revoke
    @type version_number: integer

    @raise KeyczarError: if invalid version number or key is not inactive.
    """
    version = self.metadata.GetVersion(version_number)
    if version.status == keyinfo.INACTIVE:
      self.metadata.RemoveVersion(version_number)
    else:
      raise errors.KeyczarError("Can't revoke key if not inactive.")

  def PublicKeyExport(self, dest, mock=None):
    """Export the public keys corresponding to our key set to destination."""
    kmd = self.metadata
    pubkmd = None
    if kmd.type == keyinfo.DSA_PRIV and kmd.purpose == keyinfo.SIGN_AND_VERIFY:
      pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.VERIFY, keyinfo.DSA_PUB)
    elif kmd.type == keyinfo.RSA_PRIV:
      if kmd.purpose == keyinfo.DECRYPT_AND_ENCRYPT:
        pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.ENCRYPT, keyinfo.RSA_PUB)
      elif kmd.purpose == keyinfo.SIGN_AND_VERIFY:
        pubkmd = keydata.KeyMetadata(kmd.name, keyinfo.VERIFY, keyinfo.RSA_PUB)
    if pubkmd is None:
      raise errors.KeyczarError("Cannot export public key")
    for v in self.versions:
      pubkmd.AddVersion(v)
      pubkey = self.GetKey(v).public_key
      if mock:  # only for testing
        mock.SetPubKey(v.version_number, pubkey)
      else:
        util.WriteFile(str(pubkey), os.path.join(dest, str(v.version_number)))
    if mock: # only for testing
      mock.pubkmd = pubkmd
    else:
      util.WriteFile(str(pubkmd), os.path.join(dest, "meta"))

  def Write(self, writer, encrypter=None):
    """
    Write this key set to the specified location.

    @param writer: where to write the key set
    @type writer: Writer or file path (deprecated)

    @param encrypter: which encryption to use for this key set. Use None to
    write an unencrypted key set.
    @type encrypter: Encrypter
    """
    if isinstance(writer, basestring):
      writer = writers.CreateWriter(writer)
      warnings.warn(
        'Using a string as the writer is deprecated. Use writers.CreateWriter',
        DeprecationWarning)
    self.metadata.encrypted = (encrypter is not None)
    writer.WriteMetadata(self.metadata)
    for v in self.versions:
      writer.WriteKey(self.GetKey(v), v.version_number, encrypter)

class Encrypter(Keyczar):
  """Capable of encrypting only."""

  @staticmethod
  def Read(location):
    """
    Return an Encrypter object created from FileReader at given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: an Encrypter to manage the keys stored at the given location and
      perform encryption functions.
    @rtype: L{Encrypter}
    """
    return Encrypter(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes encrypting."""
    return purpose == keyinfo.ENCRYPT or purpose == keyinfo.DECRYPT_AND_ENCRYPT

  def Encrypt(self, data, encoder=util.Base64WSEncode):
    """
    Encrypt the data and return the ciphertext.

    @param data: message to encrypt
    @type data: string

    @param encoder: function to perform final encoding. Defaults to Base64, use
    None for no encoding.
    @type encoder: function

    @return: ciphertext, by default Base64 encoded
    @rtype: string

    @raise NoPrimaryKeyError: if no primary key can be found to encrypt
    """
    encrypting_key = self.primary_key
    if encrypting_key is None:
      raise errors.NoPrimaryKeyError()
    ciphertext = encrypting_key.Encrypt(data)
    return encoder(ciphertext) if encoder else ciphertext

  def CreateEncryptingStreamWriter(self, output_stream,
                                   encoder=util.IncrementalBase64WSStreamWriter
                                  ):
    """
    Create an encrypting stream capable of writing a ciphertext byte stream
    containing Header|IV|Ciph|Sig.

    @param output_stream: target stream for encrypted output
    @type output_stream: 'file-like' object

    @param encoder: the encoding stream to use on the ciphertext stream.
    Defaults to base64 encoding with no padding or line breaks.
    Use None for raw bytes.
    @type encoder: 'file-like' object

    @return: an encrypting stream capable of creating a ciphertext byte stream
    @rtype: EncryptingStreamWriter
    """
    encrypting_key = self.primary_key
    if encrypting_key is None:
      raise errors.NoPrimaryKeyError()
    if encoder:
      stream = encoder(output_stream)
    else:
      stream = output_stream
    return keys.EncryptingStreamWriter(encrypting_key, stream)

class Verifier(Keyczar):
  """Capable of verifying only."""

  @staticmethod
  def Read(location):
    """
    Return a Verifier object created from FileReader at given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Verifier to manage the keys stored at the given location and
      perform verify functions.
    @rtype: L{Verifier}
    """
    return Verifier(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes verifying."""
    return purpose == keyinfo.VERIFY or purpose == keyinfo.SIGN_AND_VERIFY

  def Verify(self, data, sig, decoder=util.Base64WSDecode):
    """
    Verifies whether the signature corresponds to the given data.

    @param data: message that has been signed with sig
    @type data: string

    @param sig: Base64 string formatted as Header|Signature
    @type sig: string

    @return: True if sig corresponds to data, False otherwise.
    @rtype: boolean
    """
    sig_bytes = decoder(sig) if decoder else sig
    if len(sig_bytes) < HEADER_SIZE:
      raise errors.ShortSignatureError(len(sig_bytes))
    return self.__InternalVerify(sig_bytes[:HEADER_SIZE], sig_bytes[HEADER_SIZE:], data)

  def AttachedVerify(self, signed_data, nonce, decoder=util.Base64WSDecode):
    """
    Verifies the signature in the signed blob corresponds to the data
    in the signed blob and the provided nonce, and returns the data.

    @param signed_data: the blob, produced by AttachedSign, containing
    data and signature.
    @type signed_data: string

    @param nonce: Nonce string that was used when the signature was
    generated.  If the provided value doesn't match, verification will
    fail.
    @type sig: string

    @return: If verification succeeds, the extracted data will be returned,
    otherwise, None
    @rtype: string
    """
    decoded_data = decoder(signed_data) if decoder else signed_data

    data, offset = util.UnpackByteArray(decoded_data, HEADER_SIZE)
    signature = decoded_data[offset:]
    if self.__InternalVerify(decoded_data[:HEADER_SIZE], signature, data, nonce):
      return data
    else:
      return None

  def __InternalVerify(self, header,  signature, data, nonce = None):
    key = self._ParseHeader(header)
    return key.Verify(data + util.PackByteArray(nonce) + VERSION_BYTE, signature)


class UnversionedVerifier(Keyczar):
  """Capable of verifying unversioned, standard signatures only."""

  @staticmethod
  def Read(location):
    """
    Return a UnversionedVerifier object created from FileReader at
    given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Verifier to manage the keys stored at the given location and
      perform verify functions.
    @rtype: L{Verifier}
    """
    return UnversionedVerifier(readers.FileReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes verifying."""
    return purpose == keyinfo.VERIFY or purpose == keyinfo.SIGN_AND_VERIFY

  def Verify(self, data, sig, decoder=util.Base64WSDecode):
    """
    Verifies whether the signature corresponds to the given data. This is a
    stanard signature (i.e. HMAC-SHA1, RSA-SHA1, DSA-SHA1) that contains no
    version information, so this will try to verify with each key in a keyset.

    @param data: message that has been signed with sig
    @type data: string

    @param sig: Base64 string formatted as Header|Signature
    @type sig: string

    @return: True if sig corresponds to data, False otherwise.
    @rtype: boolean
    """
    sig_bytes = decoder(sig) if decoder else sig

    for version in self.versions:
      key = self._keys[version]
      # Try to verify with each key
      result = key.Verify(data, sig_bytes)
      if result:
        return True

    # None of the keys verified the signature
    return False

class Crypter(Encrypter):

  """Capable of encrypting and decrypting."""

  @staticmethod
  def Read(location):
    """
    Return a Crypter object created from FileReader at given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Crypter to manage the keys stored at the given location and
      perform encryption and decryption functions.
    @rtype: L{Crypter}
    """
    return Crypter(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes decrypting"""
    return purpose == keyinfo.DECRYPT_AND_ENCRYPT

  def Decrypt(self, ciphertext, decoder=util.Base64WSDecode):
    """
    Decrypts the given ciphertext and returns the plaintext.

    @param ciphertext: ciphertext to be decrypted - by default is Base64 encoded
    @type ciphertext: string

    @param decoder: function to perform decoding. Defaults to Base64, use None
    for no decoding.
    @type encoder: function

    @return: plaintext message
    @rtype: string

    @raise ShortCiphertextError: if length is too short to have Header, IV, Sig
    @raise BadVersionError: if header specifies an illegal version
    @raise BadFormatError: if header specifies an illegal format
    @raise KeyNotFoundError: if key specified in header doesn't exist
    @raise InvalidSignatureError: if the signature can't be verified
    """
    data_bytes = decoder(ciphertext) if decoder else ciphertext
    if len(data_bytes) < HEADER_SIZE:
      raise errors.ShortCiphertextError(len(data_bytes))
    key = self._ParseHeader(data_bytes[:HEADER_SIZE])
    return key.Decrypt(data_bytes)

  def CreateDecryptingStreamReader(self, output_stream,
                                   decoder=util.IncrementalBase64WSStreamReader,
                                   buffer_size=util.DEFAULT_STREAM_BUFF_SIZE):
    """
    Create a decrypting stream capable of processing a ciphertext byte stream
    containing Header|IV|Ciph|Sig into plain text.

    @param output_stream: target stream for decrypted output
    @type output_stream: 'file-like' object

    @param decoder: the decoding stream to use on the incoming stream.
    Defaults to base64 decoding with no padding or line breaks.
    Use None for handling raw bytes.
    @type decoder: 'file-like' object

    @param buffer_size: Suggested buffer size for writing data (will be adjusted
    to suit the underlying cipher.
    @type buffer_size: integer

    @return: a decrypting stream capable of reading a ciphertext byte stream and
    converting it to plaintext output
    @rtype: DecryptingStreamReader
    """
    if decoder:
      stream = decoder(output_stream)
    else:
      stream = output_stream
    return keys.DecryptingStreamReader(self, stream, buffer_size)

class Signer(Verifier):
  """Capable of both signing and verifying."""

  @staticmethod
  def Read(location):
    """
    Return a Signer object created from FileReader at given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Signer to manage the keys stored at the given location and
      perform sign and verify functions.
    @rtype: L{Signer}
    """
    return Signer(readers.CreateReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes signing."""
    return purpose == keyinfo.SIGN_AND_VERIFY

  def Sign(self, data, encoder=util.Base64WSEncode):
    """
    Sign given data and return corresponding signature.

    For message M, outputs the signature as Header|Sig(M|VersionByte).

    @param data: message to be signed
    @type data: string

    @return: signature on the data encoded as a Base64 string
    @rtype: string
    """
    signature = self.primary_key.Header() + self.__InternalSign(data)
    return encoder(signature) if encoder else signature

  def AttachedSign(self, data, nonce, encoder=util.Base64WSEncode):
    """
    Sign given data and nonce and return a blob containing both data and
    signature

    For message M, and nonce N, outputs Header|len(M)|M|Sig(M|len(N)|N|VersionByte).

    @param data: message to be signed
    @type data: string

    @param nonce: nonce to be included in the signature
    @type nonce: string

    @return: signature on the data encoded as a Base64 string
    @rtype: string
    """
    signature = self.primary_key.Header() \
                + util.PackByteArray(data) \
                + self.__InternalSign(data, nonce)
    return encoder(signature) if encoder else signature


  def __InternalSign(self, data, nonce = None):
    signing_key = self.primary_key
    if signing_key is None:
      raise errors.NoPrimaryKeyError()
    return signing_key.Sign(data + util.PackByteArray(nonce) + VERSION_BYTE)

class UnversionedSigner(UnversionedVerifier):
  """Capable of both signing and verifying. This outputs standard signatures
    (i.e. HMAC-SHA1, DSA-SHA1, RSA-SHA1) that contain no key versioning.
  """

  @staticmethod
  def Read(location):
    """
    Return an UnversionedSigner object created from FileReader at
    given location.

    @param location: pathname of the directory storing the key files
    @type location: string

    @return: a Signer to manage the keys stored at the given location and
      perform sign and verify functions.
    @rtype: L{Signer}
    """
    return UnversionedSigner(readers.FileReader(location))

  def IsAcceptablePurpose(self, purpose):
    """Only valid if purpose includes signing."""
    return purpose == keyinfo.SIGN_AND_VERIFY

  def Sign(self, data, encoder=util.Base64WSEncode):
    """
    Sign given data and return corresponding signature. This signature
    contains no header or version information.

    For message M, outputs the signature as Sig(M).

    @param data: message to be signed
    @type data: string

    @return: signature on the data encoded as a Base64 string
    @rtype: string
    """
    signing_key = self.primary_key
    if signing_key is None:
      raise errors.NoPrimaryKeyError()
    signature = signing_key.Sign(data)
    return encoder(signature) if encoder else signature


SESSION_NONCE_SIZE = 16

class _Session(object):
  """
  A utility object which holds a session key and, optionally, a nonce.  This class
  is only for use by SessionEncrypter, SessionDecrypter, SignedSessionEncrypter, and
  SignedSessionDecrypter.
  """

  @staticmethod
  def New():
    """
    Constructs and returns a new _Session instance, containing a newly-generated
    AES key and random nonce.
    """
    return _Session.__Create(keys.AesKey.Generate(), util.RandBytes(SESSION_NONCE_SIZE))

  @staticmethod
  def LoadPackedKey(packed_key_data):
    """
    Constructs and returns a new _Session instance, initialized with the key data
    extracted from the provided packed_key_data, which must have been produced by
    _Session.packed_key.
    """
    unpacked = util.UnpackMultipleByteArrays(packed_key_data)
    assert len(unpacked) == 2
    aes_key_bytes = unpacked[0]
    hmac_key_bytes = unpacked[1]
    hmac_key = keys.HmacKey(util.Base64WSEncode(hmac_key_bytes), len(hmac_key_bytes) * 8)
    session_key = keys.AesKey(util.Base64WSEncode(aes_key_bytes), hmac_key, len(aes_key_bytes) * 8,
                              keyinfo.CBC)
    return _Session.__Create(session_key, None)

  @staticmethod
  def LoadJsonSession(json_session_data):
    """
    Constructs and returns a new _Session instance, initialized with the key and nonce
    extracted from the provided json_session_data, which must have been produced by
    _Session.json.
    """
    json_dict = json.loads(json_session_data)
    aes_key_string = json.dumps(json_dict['key'])
    return _Session.__Create(keys.AesKey.Read(aes_key_string),
                             util.Base64WSDecode(json_dict['nonce']))

  @staticmethod
  def __Create(session_key, nonce):
    """
    Creates a new _Session instance, with the private fields initialized to the provided values.
    """
    session = _Session()
    session.__session_key = session_key
    session.__nonce = nonce
    return session

  @property
  def crypter(self):
    """
    Returns a Crypter which can be used to encrypt and decrypt data using the session key.
    """
    if not hasattr(self, '_crypter'):
        self._crypter = Crypter(readers.StaticKeyReader(
            self.__session_key, keyinfo.DECRYPT_AND_ENCRYPT))
    return self._crypter

  @property
  def nonce(self):
    return self.__nonce

  @property
  def packed_key(self):
    """
    Returns the session key data in a compact binary format.
    """
    return util.PackMultipleByteArrays(self.__session_key.key_bytes,
                                       self.__session_key.hmac_key.key_bytes)

  @property
  def json(self):
    """
    Returns the session key data and nonce in Json format.
    """
    aes_key_string = json.loads(str(self.__session_key))
    return json.dumps({ 'key' : aes_key_string, 'nonce' : util.Base64WSEncode(self.__nonce) })


class SessionEncrypter(object):
  """
  An Encrypter that encrypts the data with a generated AES session key.  The session key
  is in turn encrypted with a user-provided Encrypter, producing session_material, which
  must be provided to the SessionDecrypter to be able to decrypt session-encrypted data.
  """

  def __init__(self, encrypter):
    self._session = _Session.New()
    self._encrypted_session_material = encrypter.Encrypt(self._session.packed_key)

  @property
  def session_material(self):
    """
    Returns the base64-encoded, encrypted session blob that must be provided to the
    SessionDecrypter in order to decrypt data encrypted by this object.
    """
    return self._encrypted_session_material

  def Encrypt(self, plaintext, encoder=util.Base64WSEncode):
    """
    Encrypts the given plaintext with the session key and returns the base 64-encoded result.
    """
    return self._session.crypter.Encrypt(plaintext, encoder)


class SessionDecrypter(object):
  """
  A Decrypter that can decrypt data encrypted with a session key, which is obtained by
  decrypting the provided session_material using the provided Crypter.
  """

  def __init__(self, crypter, session_material):
    self._session = _Session.LoadPackedKey(crypter.Decrypt(session_material))

  def Decrypt(self, ciphertext, decoder=util.Base64WSDecode):
    """
    Decrypts the given base 64-encoded ciphertext with the session key and returns the
    decrypted plaintext.
    """
    return self._session.crypter.Decrypt(ciphertext, decoder)


class SignedSessionEncrypter(object):
  """
  An object that encrypts data with a session key, which is in turn encrypted by the provided
  encrypter, and signs the data with the provided signer.
  """

  def __init__(self, encrypter, signer):
    self._session = _Session.New()
    self._encrypted_session_material = encrypter.Encrypt(self._session.json)
    self._signer = signer

  @property
  def session_material(self):
    """
    Returns the base64-encoded, encrypted session blob that must be provided to the
    SignedSessionDecrypter in order to decrypt data encrypted by this object.
    """
    return self._encrypted_session_material

  def Encrypt(self, plaintext):
    ciphertext = self._session.crypter.Encrypt(plaintext, None)
    return self._signer.AttachedSign(ciphertext, self._session.nonce)


class SignedSessionDecrypter(object):
  """
  An object that verifies signatures on and decrypts data signed and encrypted by a
  SignedSessionEncrypter
  """

  def __init__(self, crypter, verifier, session_material):
    self._session = _Session.LoadJsonSession(crypter.Decrypt(session_material))
    self._verifier = verifier

  def Decrypt(self, signed_ciphertext):
    """
    Verifies the signature on the given ciphertext and, if successful, decrypts it and
    returns the decrypted plaintext.  If verification fails, returns None.
    """
    ciphertext = self._verifier.AttachedVerify(signed_ciphertext, self._session.nonce)
    if not ciphertext:
      return None
    return self._session.crypter.Decrypt(ciphertext, None)
