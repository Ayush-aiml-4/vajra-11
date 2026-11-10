/**
 * VAJRA — Authentication Rate Limiting & Brute-Force Protection
 * Prompt 0003: Rate-limits repeated login attempts per IP and account to prevent credential stuffing.
 */

interface RateBucket {
  count: number;
  resetAtMs: number;
}

export class SlidingWindowRateLimiter {
  private readonly buckets = new Map<string, RateBucket>();
  private readonly maxAttempts: number;
  private readonly windowMs: number;

  constructor(params: { maxAttempts: number; windowMs: number }) {
    this.maxAttempts = params.maxAttempts;
    this.windowMs = params.windowMs;
  }

  public check(
    key: string,
    nowMs: number = Date.now()
  ): { allowed: boolean; remaining: number; retryAfterSeconds: number } {
    const existing = this.buckets.get(key);

    if (!existing || nowMs >= existing.resetAtMs) {
      return {
        allowed: true,
        remaining: this.maxAttempts,
        retryAfterSeconds: 0,
      };
    }

    if (existing.count >= this.maxAttempts) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAtMs - nowMs) / 1000)),
      };
    }

    return {
      allowed: true,
      remaining: this.maxAttempts - existing.count,
      retryAfterSeconds: 0,
    };
  }

  public recordAttempt(key: string, nowMs: number = Date.now()): void {
    const existing = this.buckets.get(key);
    if (!existing || nowMs >= existing.resetAtMs) {
      this.buckets.set(key, {
        count: 1,
        resetAtMs: nowMs + this.windowMs,
      });
    } else {
      existing.count += 1;
    }
  }

  public reset(key: string): void {
    this.buckets.delete(key);
  }
}
