package keyczar;

public class CryptPerformanceTest {
  private static final String TEST_DATA = "./testdata";
  
  private static void displayPerformance(long start, long end, int size,
      int trials) {
    long duration = end - start;
    float averageOperation = ((float) duration) / trials;
    int data = size * trials;
    float throughput = ((float)data * 1000) / (1024*1024*duration);
    System.out.print(trials);
    System.out.print("\t");
    System.out.print(size);
    System.out.print("\t");
    System.out.print(duration);
    System.out.print("\t\t");
    System.out.print(averageOperation);
    System.out.print("\t\t");
    System.out.print(throughput);
    System.out.println();
  }
  
  private static void testAesPerformance(int size, int trials)
      throws KeyczarException {
    Crypter crypt = new Crypter(TEST_DATA + "/aes");
    byte[] input = new byte[size];
    long start = System.currentTimeMillis();
    for (int i = 0; i < trials; i++) {
      byte[] ciphertext = crypt.encrypt(input);
    }
    long end = System.currentTimeMillis();
    displayPerformance(start, end, size, trials);
  }
  
  public static void main(String[] args) throws KeyczarException {
    int trials = 50000;
    int[] sizes = {10, 128, 1024, 2048};
    System.out.println("Aes Test");
    System.out.println("Trials \tSize \tDuration (ms)\tAverage (ms)\tThroughput (MB/s)");
    for (int s : sizes) {
      testAesPerformance(trials, s);
    }
  }
}
