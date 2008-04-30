package keyczar.internal;

import keyczar.internal.Constants;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ConstantsTest {
  @Test
  public void testGetVersion() {
    assertEquals(Constants.getVersion(), 1);
  }
  
  @Test
  public void testGetHeaderSize() {
    assertEquals(Constants.getHeaderSize(), 5);
  }

  @Test
  public void testGetDigestSize() {
    assertEquals(Constants.getDigestSize(), 20);
  }
}
