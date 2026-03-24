# Rate Limiting Implementation
Protect your API from abuse with rate limiting.

## Rate limiting strategies
- **Fixed window**: Count requests in fixed time windows (simple but susceptible to burst attacks at window boundaries)
- **Sliding window**: More accurate, prevents boundary bursts
- **Token bucket**: Allows controlled bursts while enforcing average rate

## Redis-based sliding window
```python
import redis
import time

def is_rate_limited(user_id: str, limit: int = 100, window: int = 60) -> bool:
    r = redis.Redis()
    key = f"rate:{user_id}"
    now = time.time()
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - window)
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window)
    results = pipe.execute()
    return results[2] > limit
```

## Headers to include
Return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers so clients can adapt their request rate.
