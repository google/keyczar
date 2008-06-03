// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.keyczar.interfaces.Stream;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

class StreamCache<T extends Stream> {
  private final ConcurrentHashMap<KeyczarKey, StreamQueue<T>> cacheMap = 
    new ConcurrentHashMap<KeyczarKey, StreamQueue<T>>();
    
  void put(KeyczarKey key, T s) {
    getQueue(key).add(s);
  }
  
  T get(KeyczarKey key) {
    return getQueue(key).poll();
  }
  
  StreamQueue<T> getQueue(KeyczarKey key) {
    StreamQueue<T> queue = cacheMap.get(key);
    if (queue != null) {
      return queue;

    }
    StreamQueue<T> freshQueue = new StreamQueue<T>(); 
    queue = cacheMap.putIfAbsent(key, freshQueue);
    if (queue != null) {
      // Another thread already inserted a fresh queue with this key. 
      return queue;
    }
    return freshQueue;
  }
}

class StreamQueue<T extends Stream> extends ConcurrentLinkedQueue<T> {

}