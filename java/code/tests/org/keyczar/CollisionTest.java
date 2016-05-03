package org.keyczar;

import java.io.RandomAccessFile;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.keyczar.interfaces.KeyczarReader;
import org.keyczar.util.Base64Coder;
import org.keyczar.util.Clock;

import junit.framework.TestCase;


public class CollisionTest extends TestCase {
    private static final Logger LOG = Logger.getLogger(CollisionTest.class);
    private static final String TEST_DATA = "./testdata/key-collision";
    private String input = "This is some test data";
    
    private final void testDecrypt(String subDir) throws Exception {
        testDecrypt(new KeyczarFileReader(testData(subDir)), subDir);
    }
    
    private String testData(String subDir){
      return TEST_DATA + subDir;
    }

    private final void testDecrypt(KeyczarReader reader, String subDir)
        throws Exception {
      Crypter crypter = new Crypter(reader);
      RandomAccessFile activeInput =
        new RandomAccessFile(testData(subDir) + "/1.out", "r");
      String activeCiphertext = activeInput.readLine(); 
      activeInput.close();
      RandomAccessFile primaryInput =
        new RandomAccessFile(testData(subDir) + "/2.out", "r");
      String primaryCiphertext = primaryInput.readLine();
      primaryInput.close();
      String activeDecrypted = crypter.decrypt(activeCiphertext);
      assertEquals(input, activeDecrypted);
      String primaryDecrypted = crypter.decrypt(primaryCiphertext);
      assertEquals(input, primaryDecrypted);
    }
    
    private final void testVerify(String subDir) throws Exception {
        Verifier verifier = new Verifier(testData(subDir));
        RandomAccessFile activeInput =
          new RandomAccessFile(testData(subDir) + "/1.out", "r");
        String activeSignature = activeInput.readLine(); 
        activeInput.close();
        RandomAccessFile primaryInput =
          new RandomAccessFile(testData(subDir) + "/2.out", "r");
        String primarySignature = primaryInput.readLine();
        primaryInput.close();

        assertTrue(verifier.verify(input, activeSignature));
        assertTrue(verifier.verify(input, primarySignature));
     }
    
    private final void testVerifyAttached(String subDir,String hidden) throws Exception {
      Verifier verifier = new Verifier(testData(subDir));
      String hiddenExt="";
      if(hidden != "")
        hiddenExt = "." + hidden;
        RandomAccessFile activeInput =
          new RandomAccessFile(testData(subDir) + "/1"+hiddenExt+".attached", "r");
        String activeSignature = activeInput.readLine(); 
        activeInput.close();
        
        RandomAccessFile primaryInput =
              new RandomAccessFile(testData(subDir) + "/2"+hiddenExt+".attached", "r");
            String priarySignature = primaryInput.readLine(); 
            primaryInput.close();
        
        assertTrue(verifier.attachedVerify(Base64Coder.decodeWebSafe(activeSignature), 
            hidden.getBytes(Keyczar.DEFAULT_ENCODING)));
        
        assertTrue(verifier.attachedVerify(Base64Coder.decodeWebSafe(priarySignature), 
            hidden.getBytes(Keyczar.DEFAULT_ENCODING)));
    }
    
    public class EarlyClock implements Clock{
      public long now(){
        return 1356087960000L;
      }
    }
    
    public class LateClock implements Clock{
      public long now(){
        return 1356088560000L;
      }
    }
    
    private final void testTimeoutVerifier(String subDir) throws Exception {
      TimeoutVerifier verifier = new TimeoutVerifier(testData(subDir));
      verifier.setClock(new EarlyClock());
        RandomAccessFile activeInput =
          new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
        String activeSignature = activeInput.readLine(); 
        activeInput.close();
        
        RandomAccessFile primaryInput =
              new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
            String primarySignature = primaryInput.readLine(); 
            primaryInput.close();
    
        assertTrue(verifier.verify(input, activeSignature));
        assertTrue(verifier.verify(input, primarySignature));
    }
    
      private final void testTimeoutVerifierExpired(String subDir) throws Exception {
        TimeoutVerifier verifier = new TimeoutVerifier(testData(subDir));
      verifier.setClock(new LateClock());
        RandomAccessFile activeInput =
          new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
        String activeSignature = activeInput.readLine(); 
        activeInput.close();
        
        RandomAccessFile primaryInput =
        new RandomAccessFile(testData(subDir) + "/2.timeout", "r");
      String primarySignature = primaryInput.readLine(); 
        primaryInput.close();
        
        assertFalse(verifier.verify(input, activeSignature)); 
        assertFalse(verifier.verify(input, primarySignature));
    }
      
    @Test 
    public final void testHmacVerify() throws Exception {
      testVerify("/hmac");
    }
    
    @Test 
    public final void testHmacVerifyAttached() throws Exception {
      testVerifyAttached("/hmac", "");
    }
    
    @Test 
    public final void testHmacVerifyAttachedSecret() throws Exception {
      testVerifyAttached("/hmac", "secret");
    }
    
    @Test 
    public final void testHmacVerifyTimeoutSuccess() throws Exception {
      testTimeoutVerifier("/hmac");
    }
    
    @Test 
    public final void testHmacVerifyTimeoutExpired() throws Exception {
      testTimeoutVerifierExpired("/hmac");
    }
    
    
    @Test 
    public final void testDsaVerify() throws Exception {
      testVerify("/dsa");
    }
    
    @Test 
    public final void testDsaVerifyAttached() throws Exception {
      testVerifyAttached("/dsa", "");
    }
    
    @Test 
    public final void tesDsaVerifyAttachedSecret() throws Exception {
      testVerifyAttached("/dsa", "secret");
    }
    
    @Test 
    public final void testDsaVerifyTimeoutSuccess() throws Exception {
      testTimeoutVerifier("/dsa");
    }
    
    @Test 
    public final void testDsaVerifyTimeoutExpired() throws Exception {
      testTimeoutVerifierExpired("/dsa");
    }
    
    @Test 
    public final void testRsaVerify() throws Exception {
      testVerify("/rsa-sign");
    }
    
    @Test 
    public final void testRsaVerifyAttached() throws Exception {
      testVerifyAttached("/rsa-sign", "");
    }
    
    @Test 
    public final void tesRsaVerifyAttachedSecret() throws Exception {
      testVerifyAttached("/rsa-sign", "secret");
    }
    
    @Test 
    public final void testRsaVerifyTimeoutSuccess() throws Exception {
      testTimeoutVerifier("/rsa-sign");
    }
    
    @Test 
    public final void testRsaVerifyTimeoutExpired() throws Exception {
      testTimeoutVerifierExpired("/rsa-sign");
    }
    
    @Test
    public final void testAesDecrypt() throws Exception {
      testDecrypt("/aes");
    }
    
    @Test
    public final void testRsaDecrypt() throws Exception {
      testDecrypt("/rsa");
    }
    
    
}
