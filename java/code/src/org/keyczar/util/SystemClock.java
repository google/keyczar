package org.keyczar.util;

public class SystemClock implements Clock {
	public long now() {
		return System.currentTimeMillis();
	}
}
