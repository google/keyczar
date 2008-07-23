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


import org.keyczar.Crypter;
import org.keyczar.Signer;
import org.keyczar.exceptions.KeyczarException;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class SymmetricPerformanceTest {
  enum Tests { HMAC, AES }
  
  private static final String TEST_DATA = "./testdata";
  static final int NUM_THREADS = 3;
  static final int NUM_ITERATIONS = 30000;
  static volatile boolean caughtException;
  
  private static void displayPerformance(long start, long end, int size,
      int trials) {
    System.out.println("Trials \tSize \tDuration (ms)\tAverage (ms)\tThroughput (MB/s)");
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
  
  private static void testHmacPerformance(int size, int trials, int numThreads)
      throws KeyczarException, InterruptedException {
    Signer signer = new Signer(TEST_DATA + "/hmac");
    ArrayList<Thread> threads = new ArrayList<Thread>(numThreads);
    for (int i = 0; i < NUM_THREADS; i++) {
      SignerRunnable signerRunnable = new SignerRunnable(signer, trials, size);
      Thread t = new Thread(signerRunnable);
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
    int[] sizes = {10, 128, 1024, 2048, 4096};
    System.out.println("Aes Test");
    for (int s : sizes) {
      long start = System.currentTimeMillis();
      testAesPerformance(NUM_ITERATIONS, s, NUM_THREADS);
      long end = System.currentTimeMillis();
      displayPerformance(start, end, s, NUM_ITERATIONS * NUM_THREADS);
    }
    System.out.println("Hmac Test");
    for (int s : sizes) {
      long start = System.currentTimeMillis();
      testHmacPerformance(NUM_ITERATIONS, s, NUM_THREADS);
      long end = System.currentTimeMillis();
      displayPerformance(start, end, s, NUM_ITERATIONS * NUM_THREADS);
    }
  }
  
  static class SignerRunnable implements Runnable {
    private Signer signer;
    private int size;
    private int trials;
    private ByteBuffer input;
    private ByteBuffer output;

    SignerRunnable(Signer signer, int size, int trials) {
      this.input = ByteBuffer.wrap(new byte[size]);
      this.output = ByteBuffer.allocate(25);
      this.signer = signer;
      this.size = size;
      this.trials = trials;
    }

   public void run() {
      try {
        for (int i = 0; i < trials; i++) {
          signer.sign(input, output);
          input.rewind();
          output.rewind();
        }
      } catch (KeyczarException e) {
        e.printStackTrace();
      }
      }
    }
  
  static class CrypterRunnable implements Runnable {
    private Crypter crypter;
    private int size;
    private int trials;
    private ByteBuffer input;
    private ByteBuffer output;

    CrypterRunnable(Crypter crypter, int size, int trials) {
      this.input = ByteBuffer.wrap(new byte[size]);
      this.output = ByteBuffer.allocate(size + 58);
      this.crypter = crypter;
      this.size = size;
      this.trials = trials;
    }

   public void run() {
      try {
        for (int i = 0; i < trials; i++) {
          crypter.encrypt(input, output);
          input.rewind();
          output.rewind();
        }
      } catch (KeyczarException e) {
        e.printStackTrace();
      }
      }
    }
}
