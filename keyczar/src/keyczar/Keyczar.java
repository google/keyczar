package keyczar;

/**
 * Manages a Keyczar key set. Keys will not be read from a KeyczarReader until
 * the read() method is called.
 *
 * @author steveweis@gmail.com (Steve Weis)
 */
public abstract class Keyczar {
  private final KeyczarReader reader;
  
  /**
   * Instantiates a new Keyczar object by passing it a Keyczar reader object 
   * 
   * @param reader A KeyczarReader to read keys from
   */
  public Keyczar(KeyczarReader reader) {
    this.reader = reader;
  }
  
  public void read() {
    // Reads keys from the KeyczarReader
  }
}
