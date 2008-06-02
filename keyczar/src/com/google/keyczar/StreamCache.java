// Keyczar (http://code.google.com/p/keyczar/) 2008

package com.google.keyczar;

import com.google.keyczar.interfaces.Stream;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

class StreamCache<T extends Stream> {
  private final ConcurrentHashMap<Integer, StreamQueue<T>> cacheMap = 
    new ConcurrentHashMap<Integer, StreamQueue<T>>();
    
  void put(Integer key, T s) {
    getQueue(key).add(s);
  }
  
  T get(Integer key) {
    return getQueue(key).poll();
  }
  
  ConcurrentLinkedQueue<T> getQueue(Integer key) {
    StreamQueue<T> queue = cacheMap.get(key);
    if (queue == null) {
      queue = new StreamQueue<T>(); 
      cacheMap.put(key, queue);
    }
    return queue;
  }
}

class StreamQueue<T extends Stream> extends ConcurrentLinkedQueue<T> {
  
}