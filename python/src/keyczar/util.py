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
Utility functions for keyczar package.

@author: arkajit.dey@gmail.com (Arkajit Dey)
"""

import base64
import cPickle
import codecs
import functools
import math
import os
import struct
import warnings
import sys

try:
  # Import hashlib if Python >= 2.5
  from hashlib import sha1
except ImportError:
  from sha import sha as sha1

try:
  # check for presence of blocking I/O module
  from io import BlockingIOError
except ImportError:
  class BlockingIOError(IOError):

    """Exception raised when I/O would block on a non-blocking I/O stream."""

    def __init__(self, errno, strerror, characters_written=0):
      super(IOError, self).__init__(errno, strerror)
      if not isinstance(characters_written, (int, long)):
        raise TypeError("characters_written must be a integer")
      self.characters_written = characters_written

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ

import errors

try:
  from abc import ABCMeta, abstractmethod, abstractproperty
except ImportError:
  # to keep compatible with older Python versions.
  class ABCMeta(type):
    pass

  def abstractmethod(funcobj):
    return funcobj

  def abstractproperty(funcobj):
    return property(funcobj)

HLEN = sha1().digest_size  # length of the hash output

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
SHA1RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
SHA1_OID = univ.ObjectIdentifier('1.3.14.3.2.26')

# the standard buffer size for streaming
DEFAULT_STREAM_BUFF_SIZE = 4096

# environment variable that holds a list of additional plugin backend paths
BACKEND_PATHS_ENV_VAR = 'KEYCZAR_BACKEND_PATHS'

def ASN1Sequence(*vals):
  seq = univ.Sequence()
  for i in range(len(vals)):
    seq.setComponentByPosition(i, vals[i])
  return seq

def ParseASN1Sequence(seq):
  return [seq.getComponentByPosition(i) for i in range(len(seq))]

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
  seq = ParseASN1Sequence(decoder.decode(Base64WSDecode(pkcs8))[0])
  if len(seq) != 3:  # need three fields in PrivateKeyInfo
    raise errors.KeyczarError("Illegal PKCS8 String.")
  version = int(seq[0])
  if version != 0:
      raise errors.KeyczarError("Unrecognized PKCS8 Version")
  [oid, alg_params] = ParseASN1Sequence(seq[1])
  key = decoder.decode(seq[2])[0]
  # Component 2 is an OCTET STRING which is further decoded
  params = {}
  if oid == RSA_OID:
    key = ParseASN1Sequence(key)
    version = int(key[0])
    if version != 0:
      raise errors.KeyczarError("Unrecognized RSA Private Key Version")
    for i in range(len(RSA_PARAMS)):
      params[RSA_PARAMS[i]] = long(key[i+1])
  elif oid == DSA_OID:
    alg_params = ParseASN1Sequence(alg_params)
    for i in range(len(DSA_PARAMS)):
      params[DSA_PARAMS[i]] = long(alg_params[i])
    params['x'] = long(key)
  else:
    raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")
  return params

def ExportRsaPkcs8(params):
  oid = ASN1Sequence(RSA_OID, univ.Null())
  key = univ.Sequence().setComponentByPosition(0, univ.Integer(0))  # version
  for i in range(len(RSA_PARAMS)):
    key.setComponentByPosition(i+1, univ.Integer(params[RSA_PARAMS[i]]))
  octkey = encoder.encode(key)
  seq = ASN1Sequence(univ.Integer(0), oid, univ.OctetString(octkey))
  return Base64WSEncode(encoder.encode(seq))

def ExportDsaPkcs8(params):
  alg_params = univ.Sequence()
  for i in range(len(DSA_PARAMS)):
    alg_params.setComponentByPosition(i, univ.Integer(params[DSA_PARAMS[i]]))
  oid = ASN1Sequence(DSA_OID, alg_params)
  octkey = encoder.encode(univ.Integer(params['x']))
  seq = ASN1Sequence(univ.Integer(0), oid, univ.OctetString(octkey))
  return Base64WSEncode(encoder.encode(seq))

#NOTE: not full X.509 certificate, just public key info
#SubjectPublicKeyInfo  ::=  SEQUENCE  {
#        algorithm            AlgorithmIdentifier,
#        subjectPublicKey     BIT STRING  }
def ParseX509(x509):
  seq = ParseASN1Sequence(decoder.decode(Base64WSDecode(x509))[0])
  if len(seq) != 2:  # need two fields in SubjectPublicKeyInfo
    raise errors.KeyczarError("Illegal X.509 String.")
  [oid, alg_params] = ParseASN1Sequence(seq[0])
  pubkey = decoder.decode(univ.OctetString(BinToBytes(seq[1].
                                                      prettyPrint()[2:-3])))[0]
  # Component 1 should be a BIT STRING, get raw bits by discarding extra chars,
  # then convert to OCTET STRING which can be ASN.1 decoded
  params = {}
  if oid == RSA_OID:
    [params['n'], params['e']] = [long(x) for x in ParseASN1Sequence(pubkey)]
  elif oid == DSA_OID:
    vals = [long(x) for x in ParseASN1Sequence(alg_params)]
    for i in range(len(DSA_PARAMS)):
      params[DSA_PARAMS[i]] = vals[i]
    params['y'] = long(pubkey)
  else:
    raise errors.KeyczarError("Unrecognized AlgorithmIdentifier: not RSA/DSA")
  return params

def ExportRsaX509(params):
  oid = ASN1Sequence(RSA_OID, univ.Null())
  key = ASN1Sequence(univ.Integer(params['n']), univ.Integer(params['e']))
  binkey = BytesToBin(encoder.encode(key))
  pubkey = univ.BitString("'%s'B" % binkey)  # needs to be a BIT STRING
  seq = ASN1Sequence(oid, pubkey)
  return Base64WSEncode(encoder.encode(seq))

def ExportDsaX509(params):
  alg_params = ASN1Sequence(univ.Integer(params['p']),
                            univ.Integer(params['q']),
                            univ.Integer(params['g']))
  oid = ASN1Sequence(DSA_OID, alg_params)
  binkey = BytesToBin(encoder.encode(univ.Integer(params['y'])))
  pubkey = univ.BitString("'%s'B" % binkey)  # needs to be a BIT STRING
  seq = ASN1Sequence(oid, pubkey)
  return Base64WSEncode(encoder.encode(seq))

def MakeDsaSig(r, s):
  """
  Given the raw parameters of a DSA signature, return a Base64 signature.

  @param r: parameter r of DSA signature
  @type r: long int

  @param s: parameter s of DSA signature
  @type s: long int

  @return: raw byte string formatted as an ASN.1 sequence of r and s
  @rtype: string
  """
  seq = ASN1Sequence(univ.Integer(r), univ.Integer(s))
  return encoder.encode(seq)

def ParseDsaSig(sig):
  """
  Given a raw byte string, return tuple of DSA signature parameters.

  @param sig: byte string of ASN.1 representation
  @type sig: string

  @return: parameters r, s as a tuple
  @rtype: tuple

  @raise KeyczarErrror: if the DSA signature format is invalid
  """
  seq = decoder.decode(sig)[0]
  if len(seq) != 2:
    raise errors.KeyczarError("Illegal DSA signature.")
  r = long(seq.getComponentByPosition(0))
  s = long(seq.getComponentByPosition(1))
  return (r, s)

def MakeEmsaMessage(msg, modulus_size):
  """Algorithm EMSA_PKCS1-v1_5 from PKCS 1 version 2"""
  magic_sha1_header = [0x30, 0x21, 0x30, 0x9, 0x6, 0x5, 0x2b, 0xe, 0x3, 0x2,
                       0x1a, 0x5, 0x0, 0x4, 0x14]
  encoded = "".join([chr(c) for c in magic_sha1_header]) + Hash(msg)
  pad_string = chr(0xFF) * (modulus_size / 8 - len(encoded) - 3)
  return chr(1) + pad_string + chr(0) + encoded

def BinToBytes(bits):
  """Convert bit string to byte string."""
  bits = _PadByte(bits)
  octets = [bits[8 * i:8 * (i + 1)] for i in range(len(bits) / 8)]
  return "".join([chr(int(x, 2)) for x in octets])

def BytesToBin(byte_string):
  """Convert byte string to bit string."""
  return "".join([_PadByte(IntToBin(ord(byte))) for byte in byte_string])

def _PadByte(bits):
  """Pad a string of bits with zeros to make its length a multiple of 8."""
  r = len(bits) % 8
  return ((8 - r) % 8) * '0' + bits

def IntToBin(n):
  if n == 0 or n == 1:
    return str(n)
  elif n % 2 == 0:
    return IntToBin(n / 2) + "0"
  else:
    return IntToBin(n / 2) + "1"

def BigIntToBytes(n):
  """Return a big-endian byte string representation of an arbitrary length n."""
  chars = []
  while (n > 0):
    chars.append(chr(n % 256))
    n = n >> 8
  chars.reverse()
  return "".join(chars)

def IntToBytes(n):
  """Return byte string of 4 big-endian ordered byte_array representing n."""
  byte_array = [m % 256 for m in [n >> 24, n >> 16, n >> 8, n]]
  return "".join([chr(b) for b in byte_array])  # byte array to byte string

def BytesToLong(byte_string):
  l = len(byte_string)
  return long(sum([ord(byte_string[i]) * 256**(l - 1 - i) for i in range(l)]))

def Xor(a, b):
  """Return a ^ b as a byte string where a and b are byte strings."""
  # pad shorter byte string with zeros to make length equal
  m = max(len(a), len(b))
  if m > len(a):
    a = PadBytes(a, m - len(a))
  elif m > len(b):
    b = PadBytes(b, m - len(b))
  x = [ord(c) for c in a]
  y = [ord(c) for c in b]
  z = [chr(x[i] ^ y[i]) for i in range(m)]
  return "".join(z)

def PadBytes(byte_string, n):
  """Prepend a byte string with n zero bytes."""
  return n * '\x00' + byte_string

def TrimBytes(byte_string):
  """Trim leading zero bytes."""
  trimmed = byte_string.lstrip(chr(0))
  if trimmed == "":  # was a string of all zero byte_string
    return chr(0)
  else:
    return trimmed

def RandBytes(n):
  """Return n random bytes."""
  # This function requires at least Python 2.4.
  return os.urandom(n)

def Hash(*inputs):
  """Return a SHA-1 hash over a variable number of inputs."""
  md = sha1()
  for i in inputs:
    md.update(i)
  return md.digest()

def PrefixHash(*inputs):
  """Return a SHA-1 hash over a variable number of inputs."""
  md = sha1()
  for i in inputs:
    md.update(IntToBytes(len(i)))
    md.update(i)
  return md.digest()


def Encode(s):
  warnings.warn('Encode() is deprecated, use Base64WSEncode() instead', DeprecationWarning)
  return Base64WSEncode(s)


def Base64WSEncode(s):
  """
  Return Base64 web safe encoding of s. Suppress padding characters (=).

  Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
  unicode to string type first.

  @param s: string to encode as Base64
  @type s: string

  @return: Base64 representation of s.
  @rtype: string
  """
  return base64.urlsafe_b64encode(str(s)).replace("=", "")


def Decode(s):
  warnings.warn('Decode() is deprecated, use Base64WSDecode() instead', DeprecationWarning)
  return Base64WSDecode(s)


def Base64WSDecode(s):
  """
  Return decoded version of given Base64 string. Ignore whitespace.

  Uses URL-safe alphabet: - replaces +, _ replaces /. Will convert s of type
  unicode to string type first.

  @param s: Base64 string to decode
  @type s: string

  @return: original string that was encoded as Base64
  @rtype: string

  @raise Base64DecodingError: If length of string (ignoring whitespace) is one
    more than a multiple of four.
  """
  s = ''.join(s.splitlines())
  s = str(s.replace(" ", ""))  # kill whitespace, make string (not unicode)
  d = len(s) % 4
  if d == 1:
    raise errors.Base64DecodingError()
  elif d == 2:
    s += "=="
  elif d == 3:
    s += "="
  try:
    return base64.urlsafe_b64decode(s)
  except TypeError:
    # Decoding raises TypeError if s contains invalid characters.
    raise errors.Base64DecodingError()

# Struct packed byte array format specifiers used below
BIG_ENDIAN_INT_SPECIFIER = ">i"
STRING_SPECIFIER = "s"

def PackByteArray(array):
  """
  Packs the given array into a structure composed of a four-byte, big-endian
  integer containing the array length, followed by the array contents.
  """
  if array is None:
    return ''
  array_length_header = struct.pack(BIG_ENDIAN_INT_SPECIFIER, len(array))
  return array_length_header + array

def PackMultipleByteArrays(*arrays):
  """
  Packs the provided variable number of byte arrays into one array.  The
  returned array is prefixed with a count of the arrays contained, in a
  four-byte big-endian integer, followed by the arrays in sequence, each
  length-prefixed by PackByteArray().
  """
  array_count_header = struct.pack(BIG_ENDIAN_INT_SPECIFIER, len(arrays))
  array_contents = ''.join([PackByteArray(a) for a in arrays])
  return array_count_header + array_contents

def UnpackByteArray(data, offset):
  """
  Unpacks a length-prefixed byte array packed by PackByteArray() from 'data',
  starting from position 'offset'.  Returns a tuple of the data array and the
  offset of the first byte after the end of the extracted array.
  """
  array_len = struct.unpack(BIG_ENDIAN_INT_SPECIFIER, data[offset:offset + 4])[0]
  offset += 4
  return data[offset:offset + array_len], offset + array_len

def UnpackMultipleByteArrays(data):
  """
  Extracts and returns a list of byte arrays that were packed by
  PackMultipleByteArrays().
  """
  # The initial integer containing the number of byte arrays that follow is redundant.  We
  # just skip it.
  position = 4
  result = []
  while position < len(data):
    array, position = UnpackByteArray(data, position)
    result.append(array)
  assert position == len(data)
  return result

def WriteFile(data, loc):
  """
  Writes data to file at given location.

  @param data: contents to be written to file
  @type data: string

  @param loc: name of file to write to
  @type loc: string

  @raise KeyczarError: if unable to write to file because of IOError
  """
  try:
    f = open(loc, "w")
    f.write(data)
    f.close()
  except IOError:
    raise errors.KeyczarError("Unable to write to file %s." % loc)

def ReadFile(loc):
  """
  Read data from file at given location.

  @param loc: name of file to read from
  @type loc: string

  @return: contents of the file
  @rtype: string

  @raise KeyczarError: if unable to read from file because of IOError
  """
  try:
    return open(loc).read()
  except IOError:
    raise errors.KeyczarError("Unable to read file %s." % loc)

def MGF(seed, mlen):
  """
  Mask Generation Function (MGF1) with SHA-1 as hash.

  @param seed: used to generate mask, a byte string
  @type seed: string

  @param mlen: desired length of mask
  @type mlen: integer

  @return: mask, byte string of length mlen
  @rtype: string

  @raise KeyczarError: if mask length too long, > 2^32 * hash_length
  """
  if mlen > 2**32 * HLEN:
    raise errors.KeyczarError("MGF1 mask length too long.")
  output = ""
  for i in range(int(math.ceil(mlen / float(HLEN)))):
    output += Hash(seed, IntToBytes(i))
  return output[:mlen]

class BufferedIncrementalBase64WSEncoder(codecs.BufferedIncrementalEncoder):

  """
  Web-safe Base64 encodes an input in multiple steps. Each step bar the final
  one will be sized to ensure no Base64 padding is required. Any unencoded data
  outside this optimal size will be buffered.
  """

  def _buffer_encode(self, input, errors, final):
    """
    Encodes input and returns the resulting object, buffering any data that is
    beyond the optimal no-padding length unless final is True
    Implementation of abstract method in parent.

    @param input: string to encode as Base64
    @type input: string

    @param errors: required error handling scheme (see
    IncrementalBase64WSStreamWriter)

    @param final: force all data to be encoded, possibly resulting in padding
    #type final: boolean

    @return: (Base64 representation of input, length consumed)
    @rtype: tuple
    """
    # Overwrite this method in subclasses: It must encode input
    # and return an (output, length consumed) tuple
    if not final:
      # only output exact multiples of 3-bytes => no padding
      len_to_write = 3 * (len(input) / 3)
    else:
      len_to_write = len(input)
    return (Base64WSEncode(input[:len_to_write]), len_to_write)

  def encode(self, input, final=False):
    """
    Encodes input and returns the resulting object.
    Note that unless final is True the returned data may not encode all the
    supplied input as it encodes the maximum length that will not result in
    padding. The remaining data is buffered for subsequent calls to encode().

    @param input: string to encode as Base64
    @type input: string

    @param final: force all data to be encoded, possibly resulting in padding
    #type final: boolean

    @return: (Base64 representation of input, length consumed)
    @rtype: tuple
    """
    result = super(BufferedIncrementalBase64WSEncoder, self).encode(input,
                                                                  final=final)
    return (result, len(input) - len(self.buffer))

  def flush(self):
    """
    Flush this encoder, returning any buffered data

    @return: Base64 representation of buffered data
    @rtype: string
    """
    result = ('', 0)
    if self.buffer:
      result = self._buffer_encode(self.buffer, self.errors, True)
      self.buffer = ''
    return result[0]

class IncrementalBase64WSStreamWriter(codecs.StreamWriter, object):

  """
  Web-safe Base64 encodes a stream in multiple steps to an output stream. Each
  step bar the final one will be sized to ensure no Base64 padding is required.
  Any unencoded data outside this optimal size will be buffered and output when
  flush() is called.

  """
  def __init__(self, stream, errors='strict'):
    """
    Creates an IncrementalBase64WSStreamWriter instance.

    @param stream: a file-like object open for writing (binary) data.

    @param errors: required error handling scheme

    The reader may use different error handling
    schemes by providing the errors keyword argument. These
    parameters are predefined:

     'strict' - raise a ValueError (or a subclass)
     'ignore' - ignore the character and continue with the next
     'replace'- replace with a suitable replacement character
     'xmlcharrefreplace' - Replace with the appropriate XML
                           character reference.
     'backslashreplace'  - Replace with backslashed escape
                           sequences (only for encoding).

    """
    super(IncrementalBase64WSStreamWriter, self).__init__(stream, errors)
    self.encoder = BufferedIncrementalBase64WSEncoder(errors=errors)

  def close(self):
    """ Flushes and closes the stream """
    self.flush()
    super(IncrementalBase64WSStreamWriter, self).close()

  def flush(self):
    """
    Flush this stream, writing any buffered data to the output stream
    """
    result = self.encoder.flush()
    if result:
      self.stream.write(result)
      self.stream.flush()

  def encode(self, input, errors='strict'):
    """
    Base64 Encodes input and returns the resulting object.

    @param input: string to encode as Base64
    @type input: string

    @param errors: required error handling scheme (see __init__)

    @return: Base64 representation of input.
    @rtype: string
    """
    return self.encoder.encode(input)

class BufferedIncrementalBase64WSDecoder(codecs.BufferedIncrementalDecoder):

  """
  Web-safe Base64 decodes an input in multiple steps. Each step bar the final
  one will be sized to a length so that no Base64 padding is required. Any
  undecoded data outside this optimal size will be buffered.
  """

  def _buffer_decode(self, input, errors, final):
    """
    Decodes input and returns the resulting object, buffering any data that is
    beyond the optimal no-padding length unless final is True
    Implementation of abstract method in parent.

    @param input: string to decode from Base64
    @type input: string

    @param errors: required error handling scheme (see
    IncrementalBase64WSStreamReader)

    @param final: force all data to be decoded, possibly resulting in padding
    #type final: boolean

    @return: (plaintext version of input, length consumed)
    @rtype: tuple
    """
    if not final:
      # only output exact multiples of 4-bytes => no padding
      len_to_read = 4 * (len(input) / 4)
    else:
      len_to_read = len(input)
    return (Base64WSDecode(input[:len_to_read]), len_to_read)

  def decode(self, input, final=False):
    """
    Decodes input and returns the resulting object.
    Note that unless final is True the returned data may not decode all the
    supplied input as it uses the maximum length that would not require padding.
    The remaining data is buffered for subsequent calls to decode().

    @param input: string to decode from Base64
    @type input: string

    @param final: force all data to be decoded, possibly resulting in padding
    #type final: boolean

    @return: plaintext representation of input.
    @rtype: string
    """
    result = super(BufferedIncrementalBase64WSDecoder, self).decode(input,
                                                                  final=final)
    return (result, len(input))

  def flush(self):
    """
    Flush this decoder, returning any buffered data

    @return: plaintext representation of buffered data
    @rtype: string
    """
    result = ('', 0)
    if self.buffer:
      result = self._buffer_decode(self.buffer, self.errors, True)
      self.buffer = ''
    return result[0]

class IncrementalBase64WSStreamReader(codecs.StreamReader, object):

  """
  Web-safe Base64 decodes a stream in multiple steps. Each step bar the final
  one will be sized to a length so that no Base64 padding is required. Any
  undecoded data outside this optimal size will be buffered and decoded on a
  final call to read().
  """

  def __init__(self, stream, errors='strict'):
    """
    Creates an IncrementalBase64WSStreamReader instance.

    @param stream: a file-like object open for reading (binary) data.

    @param errors: required error handling scheme

    The reader may use different error handling
    schemes by providing the errors keyword argument. These
    parameters are predefined:

     'strict' - raise a ValueError (or a subclass)
     'ignore' - ignore the character and continue with the next
     'replace'- replace with a suitable replacement character
     'xmlcharrefreplace' - Replace with the appropriate XML
                           character reference.
     'backslashreplace'  - Replace with backslashed escape
                           sequences (only for encoding).

    """
    super(IncrementalBase64WSStreamReader, self).__init__(stream, errors)
    self.decoder = BufferedIncrementalBase64WSDecoder(errors=errors)

  def read(self, size=-1, chars=-1, firstline=False):
    """
    Decodes data from the input stream and returns the resulting object.

    @param chars: the number of characters to read from the stream. read() will
    never return more than chars characters, but it might return less, if there
    are not enough characters available.
    Will return None if the underlying stream does i.e. is non-blocking and no
    data is available.
    @type chars: integer

    @param size: indicates the approximate maximum number of bytes to read from
    the stream for decoding purposes. The decoder can modify this setting as
    appropriate. The default value -1 indicates to read and decode as much as
    possible.  size is intended to prevent having to decode huge files in one
    step.
    @type size: integer

    @param firstline: if firstline is true, and a UnicodeDecodeError happens
    after the first line terminator in the input only the first line will be
    returned, the rest of the input will be kept until the next call to read().
    @type firstline: boolean

    @return: plaintext representation of input. Returns an empty string when the
    end of the input data has been reached.
    @rtype: string
    """

    # NOTE: this is a copy of the code from Python v2.7 codecs.py tweaked to
    # handle non-blocking streams i.e. those that return None to indicate no
    # data is available but is not at EOF - see read() in the Python I/O module
    # documentation.

    # === start of codecs.py code ===
    # If we have lines cached, first merge them back into characters
    if self.linebuffer:
      self.charbuffer = "".join(self.linebuffer)
      self.linebuffer = None

    # read until we get the required number of characters (if available)
    newdata = ''
    while True:
      # can the request can be satisfied from the character buffer?
      if chars < 0:
        if size < 0:
          if self.charbuffer:
            break
        elif len(self.charbuffer) >= size:
          break
      else:
        if len(self.charbuffer) >= chars:
          break

      # we need more data
      try:
        if size < 0:
          newdata = self.stream.read()
        else:
          newdata = self.stream.read(size)
      except BlockingIOError:
        newdata = None

      if newdata is not None:
        # decode bytes (those remaining from the last call included)
        data = self.bytebuffer + newdata
        try:
          newchars, decodedbytes = self.decode(data, self.errors)
        except UnicodeDecodeError, exc:
          if firstline:
            newchars, decodedbytes = self.decode(data[:exc.start], self.errors)
            lines = newchars.splitlines(True)
            if len(lines)<=1:
              raise
          else:
            raise
        # keep undecoded bytes until the next call
        self.bytebuffer = data[decodedbytes:]
        # put new characters in the character buffer
        self.charbuffer += newchars
        # there was no data available
        if not newdata:
          break

    if chars < 0:
      # Return everything we've got
      result = self.charbuffer
      self.charbuffer = ""
    else:
      # Return the first chars characters
      result = self.charbuffer[:chars]
      self.charbuffer = self.charbuffer[chars:]

    # === end of codecs.py code ===
    if not result and newdata is None:
      result = None

    if not result and newdata == '':
      if chars != 0:
        result = self.decoder.flush()

    return result

  def decode(self, input, errors='strict'):
    """
    Decodes Base64 input and returns the resulting object.

    @param input: string to decode from Base64
    @type input: string

    @param errors: required error handling scheme (see __init__)

    @return: plaintext representation of input.
    @rtype: string
    """
    return self.decoder.decode(input)

def ImportAll(pluginpath):
  """
  Simple plugin importer - imports from the specified subdirectory under the
  util.py directory

  @param subdir: the subdirectory to load from
  @type subdir: string
  """
  if os.path.exists(pluginpath):
    pluginfiles = [fname[:-3] for fname in os.listdir(pluginpath) if
                   fname.endswith(".py")]
    if not pluginpath in sys.path:
      sys.path.append(pluginpath)
    imported_modules = [__import__('%s' %(fname)) for fname in pluginfiles]

def ImportBackends():
  """
  Simple backend plugin importer - imports from the 'backends' subdirectory
  under the util.py directory and any directories in the environment variable
  'KEYCZAR_BACKEND_PATHS', which can contain >=1 paths joined using the o/s
  """
  pluginpath = os.path.join(os.path.dirname(__file__), 'backends')
  ImportAll(pluginpath)
  xtra_paths = os.environ.get(BACKEND_PATHS_ENV_VAR, '')
  if xtra_paths:
    for path in xtra_paths.split(os.pathsep):
      ImportAll(path)
