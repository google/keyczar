package keyczar;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class KeyczarTest {
  private static final String TEST_DATA = "./testdata";

  @Before
  public void setUp() throws Exception {
  }

  @Test
  public final void testKeyczar() throws KeyczarException {
    Keyczar keyczar = new Keyczar(TEST_DATA + "/hmac");
    keyczar.read();
  }
}
