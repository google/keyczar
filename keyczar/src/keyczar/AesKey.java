// Keyczar (http://code.google.com/p/keyczar/) 2008

package keyczar;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import keyczar.interfaces.DecryptingStream;
import keyczar.interfaces.EncryptingStream;
import keyczar.interfaces.SigningStream;
import keyczar.interfaces.VerifyingStream;

/**
 * Wrapping class for AES keys
 * 
 * @author steveweis@gmail.com (Steve Weis)
 */
public class AesKey extends KeyczarKey {
  private static final String AES_ALGORITHM = "AES";
  public enum CipherMode {
    CBC(0, "AES/CBC/PKCS5Padding", true),
    CTR(1, "AES/CTR/NoPadding", true),
    ECB(2, "AES/ECB/NoPadding", false),
    DET_CBC(3, "AES/CBC/PKCS5Padding", false);

    private String jceMode;
    @Expose private int value;

    private boolean useIv;
    private CipherMode(int v, String s, boolean useIv) {
      this.value = v;
      this.jceMode = s;
      this.useIv = useIv;
    }
    static CipherMode getMode(int value) {
      switch (value) {
        case 0: return CBC;
        case 1: return CTR;
        case 2: return ECB;
        case 3: return DET_CBC;
      }
      return null;
    }

    int getValue() {
      return value;
    }
    
    String getMode() {
      return jceMode;
    }
  }
  
  
  private static final CipherMode DEFAULT_MODE = CipherMode.CBC;
  @Expose private KeyType type = KeyType.AES;
  // Default mode is CBC
  @Expose private CipherMode mode = DEFAULT_MODE;
  @Expose private String aesKeyString = "";
  @Expose private HmacKey hmacKey = new HmacKey();

  private Key aesKey;
  
  @Expose private byte[] hash = new byte[Keyczar.KEY_HASH_SIZE];
  private int hashCode;
  private int blockSize;
  
  private void init() throws KeyczarException  {
    byte[] aesBytes = Util.base64Decode(aesKeyString);
    hashCode = Util.toInt(hash);
    aesKey = new SecretKeySpec(aesBytes, AES_ALGORITHM);
    blockSize = aesBytes.length;
  }

  @Override
  protected byte[] hash() {
    return hash;
  } 
  
  @Override
  public int hashCode() {
    return hashCode;
  }
  
  @Override
  protected void read(String input) throws KeyczarException {
    AesKey copy = Util.gson().fromJson(input, AesKey.class);
    if (copy.type != getType()) {
      throw new KeyczarException("Invalid type in input: " + copy.type);
    }
    this.hash = copy.hash;
    this.type = copy.type;
    this.mode = copy.mode;
    this.aesKeyString = copy.aesKeyString;
    this.hmacKey = copy.hmacKey;
    this.hmacKey.init();
    
    // Check that the hash is correct
    byte[] aesBytes = Util.base64Decode(this.aesKeyString);
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    for (int i = 0; i < this.hash.length; i++) {
      if (hash[i] != fullHash[i]) {
        throw new KeyczarException("Hash does not match");
      }
    }
    init();
  }
  
  @Override
  public String toString() {
    return Util.gson().toJson(this);
  }

  @Override
  protected void generate() throws KeyczarException {
    byte[] aesBytes = Util.rand(getType().defaultSize() / 8);
    aesKeyString = Util.base64Encode(aesBytes);
    mode = DEFAULT_MODE;
    type = getType();
    hmacKey.generate();
    byte[] fullHash = Util.prefixHash(aesBytes, hmacKey.hash());
    System.arraycopy(fullHash, 0, hash, 0, hash.length);
  }

  @Override
  protected KeyType getType() {
    return KeyType.AES;
  }
  
  @Override
  protected Stream getStream() throws KeyczarException {
    return new AesStream();
  }

  private class AesStream extends Stream
      implements EncryptingStream, DecryptingStream {
    Cipher cipher;
    
    public AesStream() throws KeyczarException {
      try {
        cipher = Cipher.getInstance(mode.getMode());
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
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return update(input, output);
    }
    
    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return doFinal(input, output);
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
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return update(input, output);
    }

    @Override
    public int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return doFinal(input, output);
    }

    private int doFinal(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
    
    private int update(ByteBuffer input, ByteBuffer output) throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }
    
    @Override
    public int maxOutputSize(int inputLen) {
      switch(mode) {
        case ECB:
          return blockSize;
        case CTR:
          return inputLen;
        case CBC: default:
          return (inputLen / blockSize + 2) * blockSize;
      }
    }
    
    @Override
    public int ivSize() {
      switch(mode) {
        case ECB:
          return 0;
        case CTR:
          return blockSize / 2;
        case CBC: default:
          return blockSize;
      }
    }

    @Override
    public SigningStream getSigningStream() throws KeyczarException {
      return (SigningStream) hmacKey.getStream();
    }

    @Override
    public VerifyingStream getVerifyingStream() throws KeyczarException {
      return (VerifyingStream) hmacKey.getStream();
    }
  }
}

