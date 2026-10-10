package org.ourcamellia.core.security;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Token-bucket rate limiter keyed by arbitrary strings (connection id, IP, account,
 * BOT token). In-memory only — limits are per-process, documented as such. Returns
 * booleans; callers convert denials into RateLimited errors.
 */
public final class RateLimiter {

    private final int permitsPerMinute;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(int permitsPerMinute) {
        this.permitsPerMinute = Math.max(1, permitsPerMinute);
    }

    public boolean tryAcquire(String key) {
        long now = System.currentTimeMillis();
        Bucket b = buckets.computeIfAbsent(key, k -> new Bucket(now, permitsPerMinute));
        synchronized (b) {
            // refill
            long elapsed = now - b.lastRefill;
            double refill = elapsed * (permitsPerMinute / 60_000.0);
            b.tokens = Math.min(permitsPerMinute, b.tokens + refill);
            b.lastRefill = now;
            if (b.tokens >= 1) {
                b.tokens -= 1;
                return true;
            }
            return false;
        }
    }

    public void clear(String key) {
        buckets.remove(key);
    }

    private static final class Bucket {
        double tokens;
        long lastRefill;

        Bucket(long now, double full) {
            this.tokens = full; // full budget on first sighting
            this.lastRefill = now;
        }
    }
}
