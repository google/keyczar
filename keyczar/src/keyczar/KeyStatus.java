package keyczar;

// TODO: Write JavaDocs
public enum KeyStatus {
  PRIMARY(0),
  ACTIVE(1),
  SCHEDULED_FOR_REVOCATION(2);

  private int value;
  private KeyStatus(int v) {
    this.value = v;
  }
    
  static KeyStatus getStatus(int value) {
    switch (value) {
      case 0: return PRIMARY;
      case 1: return ACTIVE;
      case 2: return SCHEDULED_FOR_REVOCATION;
    }
    return null;
  }
    
  int getValue() {
    return value;
  }
}