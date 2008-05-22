// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.annotations.Expose;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import keyczar.enums.CipherMode;
import keyczar.enums.KeyType;
import keyczar.interfaces.DecryptingStream;
import keyczar.interfaces.EncryptingStream;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for AES keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
class AesKey extends KeyczarKey {
  private Key aesKey;
  private int blockSize;
  private int hashCode;
  private static final String AES_ALGORITHM = "AES";
  // Default mode is CBC
  private static final CipherMode DEFAULT_MODE = CipherMode.CBC;

  @Expose private String aesKeyString = "";
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  @Expose private HmacKey hmacKey = new HmacKey();
  @Expose private CipherMode mode = DEFAULT_MODE;
  @Expose private KeyType type = KeyType.AES;

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  @Override
  void generate() throws KeyczarException {
    byte[] aesBytes = Util.rand(getType().defaultSize() / 8);
    aesKeyString = Util.base64Encode(aesBytes);
    mode = DEFAULT_MODE;
    type = getType();
    hmacKey.generate();
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  @Override
  Stream getStream() throws KeyczarException {
    return new AesStream();
  }

  @Override
  KeyType getType() {
    return KeyType.AES;
  }

  @Override
  byte[] hash() {
    return hash;
  }

  @Override
  void read(String input) throws KeyczarException {
    AesKey copy = Util.gson().fromJson(input, AesKey.class);
    if (copy.type != getType()) {
      throw new KeyczarException("Invalid type in input: " + copy.type);
    }
    hash = copy.hash;
    type = copy.type;
    mode = copy.mode;
    aesKeyString = copy.aesKeyString;
    hmacKey = copy.hmacKey;
    hmacKey.init();

    // Check that the hash is correct
    byte[] aesBytes = Util.base64Decode(aesKeyString);
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    for (int i = 0; i < hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
    init();
  }

  private void init() throws KeyczarException {
    byte[] aesBytes = Util.base64Decode(aesKeyString);
    hashCode = Util.toInt(hash);
    aesKey = new SecretKeySpec(aesBytes, AES_ALGORITHM);
    blockSize = aesBytes.length;
  }

  private class AesStream extends Stream implements EncryptingStream,
      DecryptingStream {
    Cipher cipher;

    public AesStream() throws KeyczarException {
      try {
        cipher = Cipher.getInstance(mode.getMode());
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return doFinal(input, output);
    }

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return doFinal(input, output);
    }

    @Override
    public SigningStream getSigningStream() throws KeyczarException {
      return (SigningStream) hmacKey.getStream();
    }

    @Override
    public VerifyingStream getVerifyingStream() throws KeyczarException {
      return (VerifyingStream) hmacKey.getStream();
    }

    @Override
    public void initDecrypt(ByteBuffer input) throws KeyczarException {
      try {
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        input.get(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(ivBytes));
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public byte[] initEncrypt() throws KeyczarException {
      try {
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.getIV();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int ivSize() {
      switch (mode) {
      case ECB:
        return 0;
      case CTR:
        return blockSize / 2;
      case CBC:
      default:
        return blockSize;
      }
    }

    @Override
    public int maxOutputSize(int inputLen) {
      switch (mode) {
      case ECB:
        return blockSize;
      case CTR:
        return inputLen;
      case CBC:
      default:
        return (inputLen / blockSize + 2) * blockSize;
      }
    }

    @Override
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return update(input, output);
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return update(input, output);
    }

    private int doFinal(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    private int update(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
  }
}
