package com.google.security.keyczar;

import com.google.keyczar.Crypter;
import com.google.keyczar.exceptions.KeyczarException;

import java.util.ArrayList;

public class CryptPerformanceTest {
  private static final String TEST_DATA = "/home/sweis/workspace/Keyczar/testdata";
  static final int NUM_THREADS = 3;
  static final int NUM_ITERATIONS = 30000;
  static volatile boolean caughtException;
  
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
  
  private static void testAesPerformance(int size, int trials, int numThreads)
      throws KeyczarException, InterruptedException {
    Crypter crypter = new Crypter(TEST_DATA + "/aes");
    ArrayList<Thread> threads = new ArrayList<Thread>(numThreads);
    for (int i = 0; i < NUM_THREADS; i++) {
      CrypterRunnable crypterRunnable = new CrypterRunnable(crypter, trials, size);
      Thread t = new Thread(crypterRunnable);
      t.start();
      threads.add(t);
    }

    /* wait for all threads to finish */
    for (Thread t : threads) {
      t.join();
    }

  }
  
  public static void main(String[] args) throws KeyczarException,
      InterruptedException {
    int[] sizes = {10, 1024, 2048, 4096};
    System.out.println("Aes Test");
    System.out.println("Trials \tSize \tDuration (ms)\tAverage (ms)\tThroughput (MB/s)");
    for (int s : sizes) {
      long start = System.currentTimeMillis();
      testAesPerformance(NUM_ITERATIONS, s, NUM_THREADS);
      long end = System.currentTimeMillis();
      displayPerformance(start, end, s, NUM_ITERATIONS * NUM_THREADS);
    }
  }
  
  static class CrypterRunnable implements Runnable {
    private Crypter crypter;
    private int size;
    private int trials;

    CrypterRunnable(Crypter crypter, int size, int trials) {
      this.crypter = crypter;
      this.size = size;
      this.trials = trials;
    }

   public void run() {
     byte[] input = new byte[size];
      try {
        for (int i = 0; i < trials; i++) {
          byte[] ciphertext = crypter.encrypt(input);
        }
      } catch (KeyczarException e) {
        e.printStackTrace();
      }
      }
    }
}
