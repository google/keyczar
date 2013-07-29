/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keyczar;

import static org.keyczar.util.Util.decodeBigInteger;
import static org.keyczar.util.Util.encodeBigInteger;

import com.google.gson.annotations.Expose;

import org.keyczar.enums.RsaPadding;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.DecryptingStream;
import org.keyczar.interfaces.EncryptingStream;
import org.keyczar.interfaces.KeyType;
import org.keyczar.interfaces.SigningStream;
import org.keyczar.interfaces.Stream;
import org.keyczar.interfaces.VerifyingStream;
import org.keyczar.keyparams.RsaKeyParameters;
import org.keyczar.util.Util;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

/**
 * Wrapping class for RSA Private Keys
 *
 * @author steveweis@gmail.com (Steve Weis)
 * @author arkajit.dey@gmail.com (Arkajit Dey)
 */
public class RsaPrivateKey extends KeyczarKey implements KeyczarPrivateKey {
  private static final String KEY_GEN_ALGORITHM = "RSA";

  @Expose private final RsaPublicKey publicKey;
  @Expose private final String privateExponent;
  @Expose private final String primeP;
  @Expose private final String primeQ;
  @Expose private final String primeExponentP;
  @Expose private final String primeExponentQ;
  @Expose private final String crtCoefficient;

  private static final String SIG_ALGORITHM = "SHA1withRSA";

  private RSAPrivateCrtKey jcePrivateKey;

  static RsaPrivateKey generate(RsaKeyParameters params) throws KeyczarException {
    KeyPair keyPair = Util.generateKeyPair(KEY_GEN_ALGORITHM, params.getKeySize());
    return new RsaPrivateKey((RSAPrivateCrtKey) keyPair.getPrivate(),
        (params.getRsaPadding() == null) ? RsaPadding.OAEP : params.getRsaPadding());
  }

  static RsaPrivateKey read(String input) throws KeyczarException {
    RsaPrivateKey key = Util.gson().fromJson(input, RsaPrivateKey.class);
    return key.initFromJson();
  }

  public RsaPrivateKey(RSAPrivateCrtKey privateKey, RsaPadding padding) throws KeyczarException {
    super(privateKey.getModulus().bitLength());
    publicKey = new RsaPublicKey(privateKey, padding);
    privateExponent = encodeBigInteger(privateKey.getPrivateExponent());
    primeP = encodeBigInteger(privateKey.getPrimeP());
    primeQ = encodeBigInteger(privateKey.getPrimeQ());
    primeExponentP = encodeBigInteger(privateKey.getPrimeExponentP());
    primeExponentQ = encodeBigInteger(privateKey.getPrimeExponentQ());
    crtCoefficient = encodeBigInteger(privateKey.getCrtCoefficient());
    jcePrivateKey = privateKey;
  }

  private RsaPrivateKey() {
    super(0);
    publicKey = null;
    privateExponent = null;
    primeP = null;
    primeQ = null;
    primeExponentP = null;
    primeExponentQ = null;
    crtCoefficient = null;
    jcePrivateKey = null;
  }

  @Override
  protected Stream getStream() throws KeyczarException {
    return new RsaPrivateStream();
  }

  @Override
  public KeyType getType() {
    return DefaultKeyType.RSA_PRIV;
  }

  @Override
  protected byte[] hash() {
    return publicKey.hash();
  }

  @Override
  public KeyczarPublicKey getPublic() {
    return publicKey;
  }

  /**
   * Initialize JCE key from JSON data.  Must be called after an instance is read from JSON.
   */
  private RsaPrivateKey initFromJson() throws KeyczarException {
    publicKey.initFromJson();
    try {
      final KeyFactory keyFactory = KeyFactory.getInstance(KEY_GEN_ALGORITHM);
      final RSAPrivateCrtKeySpec spec =
          new RSAPrivateCrtKeySpec(decodeBigInteger(publicKey.modulus),
            decodeBigInteger(publicKey.publicExponent), decodeBigInteger(privateExponent),
            decodeBigInteger(primeP), decodeBigInteger(primeQ), decodeBigInteger(primeExponentP),
            decodeBigInteger(primeExponentQ), decodeBigInteger(crtCoefficient));
      jcePrivateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(spec);
      return this;
    } catch (GeneralSecurityException e) {
      throw new KeyczarException(e);
    }
  }

  @Override
  protected RSAPrivateCrtKey getJceKey() {
    return jcePrivateKey;
  }

  private class RsaPrivateStream implements SigningStream, VerifyingStream,
      DecryptingStream, EncryptingStream {
    private Cipher cipher;
    private EncryptingStream encryptingStream;
    private Signature signature;
    private VerifyingStream verifyingStream;

    public RsaPrivateStream() throws KeyczarException {
      try {
        signature = Signature.getInstance(SIG_ALGORITHM);
        verifyingStream = (VerifyingStream) publicKey.getStream();
        cipher = Cipher.getInstance(publicKey.getPadding().getCryptAlgorithm());
        encryptingStream = (EncryptingStream) publicKey.getStream();
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int digestSize() {
      return publicKey.keySizeInBytes();
    }

    @Override
    public int doFinalDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.doFinal(input, output);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int doFinalEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return encryptingStream.doFinalEncrypt(input, output);
    }

    @Override
    public SigningStream getSigningStream() throws KeyczarException {
      return encryptingStream.getSigningStream();
    }

    @Override
    public VerifyingStream getVerifyingStream() {
      return new VerifyingStream() {
        @Override
        public int digestSize() {
          return 0;
        }

        @Override
        public void initVerify() {
          // Do nothing
        }

        @Override
        public void updateVerify(ByteBuffer input) {
          // Do nothing
        }

        @Override
        public boolean verify(ByteBuffer signature) {
          // Do nothing
          return true;
        }
      };
    }

    @Override
    public void initDecrypt(ByteBuffer input) throws KeyczarException {
      try {
        cipher.init(Cipher.DECRYPT_MODE, jcePrivateKey);
      } catch (InvalidKeyException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int initEncrypt(ByteBuffer output) throws KeyczarException {
      return encryptingStream.initEncrypt(output);
    }

    @Override
    public void initSign() throws KeyczarException {
      try {
        signature.initSign(jcePrivateKey);
      } catch (GeneralSecurityException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void initVerify() throws KeyczarException {
      verifyingStream.initVerify();
    }

    @Override
    public int maxOutputSize(int inputLen) {
      return publicKey.keySizeInBytes();
    }

    @Override
    public void sign(ByteBuffer output) throws KeyczarException {
      try {
        byte[] sig = signature.sign();
        output.put(sig);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int updateDecrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      try {
        return cipher.update(input, output);
      } catch (ShortBufferException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public int updateEncrypt(ByteBuffer input, ByteBuffer output)
        throws KeyczarException {
      return encryptingStream.updateEncrypt(input, output);
    }

    @Override
    public void updateSign(ByteBuffer input) throws KeyczarException {
      try {
        signature.update(input);
      } catch (SignatureException e) {
        throw new KeyczarException(e);
      }
    }

    @Override
    public void updateVerify(ByteBuffer input) throws KeyczarException {
      verifyingStream.updateVerify(input);
    }

    @Override
    public boolean verify(ByteBuffer sig) throws KeyczarException {
      return verifyingStream.verify(sig);
    }
  }
}
