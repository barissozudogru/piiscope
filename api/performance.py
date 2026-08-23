"""Performance optimization utilities for the privacy risk detection application.

This module provides caching, connection pooling, and other performance
enhancements to improve application scalability and responsiveness.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

import redis
from sqlalchemy.orm import Session

from .config import settings
from .logging_config import log_performance_metric

F = TypeVar("F", bound=Callable[..., Any])


class MemoryCache:
    """Simple in-memory cache with TTL support."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: dict[str, dict[str, Any]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl

    def _is_expired(self, entry: dict[str, Any]) -> bool:
        """Check if cache entry is expired."""
        return datetime.now(timezone.utc) > entry["expires"]

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        now = datetime.now(timezone.utc)
        expired_keys = [key for key, entry in self.cache.items() if now > entry["expires"]]
        for key in expired_keys:
            del self.cache[key]

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        if key not in self.cache:
            return None

        entry = self.cache[key]
        if self._is_expired(entry):
            del self.cache[key]
            return None

        entry["last_accessed"] = datetime.now(timezone.utc)
        return entry["value"]

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache."""
        if len(self.cache) >= self.max_size:
            self._cleanup_expired()

            # If still at max size, remove least recently accessed
            if len(self.cache) >= self.max_size:
                lru_key = min(self.cache.keys(), key=lambda k: self.cache[k]["last_accessed"])
                del self.cache[lru_key]

        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl or self.default_ttl)
        self.cache[key] = {
            "value": value,
            "expires": expires,
            "last_accessed": datetime.now(timezone.utc),
        }

    def delete(self, key: str) -> None:
        """Remove key from cache."""
        self.cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()


class RedisCache:
    """Redis-based cache for distributed caching."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.default_ttl = 300

    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage."""
        return json.dumps(value, default=str).encode("utf-8")

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage."""
        return json.loads(data.decode("utf-8"))

    def get(self, key: str) -> Any | None:
        """Get value from Redis cache."""
        try:
            data = self.redis.get(f"cache:{key}")
            if data is None:
                return None
            return self._deserialize(data)
        except Exception as e:
            logger.warning(f"Redis get error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in Redis cache."""
        try:
            serialized = self._serialize(value)
            self.redis.setex(f"cache:{key}", ttl or self.default_ttl, serialized)
        except Exception as e:
            logger.warning(f"Redis cache set error: {e}")

    def delete(self, key: str) -> None:
        """Remove key from Redis cache."""
        try:
            self.redis.delete(f"cache:{key}")
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")

    def clear_pattern(self, pattern: str) -> None:
        """Clear all keys matching pattern."""
        try:
            keys = self.redis.keys(f"cache:{pattern}")
            if keys:
                self.redis.delete(*keys)
        except Exception as e:
            logger.warning(f"Redis cache error: {e}")


# Global cache instances
memory_cache = MemoryCache()
redis_cache: RedisCache | None = None


def init_redis_cache() -> None:
    """Initialize Redis cache if available."""
    global redis_cache
    try:
        r = redis.from_url(settings.redis_url)
        r.ping()  # Test connection
        redis_cache = RedisCache(r)
    except Exception as e:
        logger.warning(f"Redis get error: {e}")
        redis_cache = None


def cache_key(*args, **kwargs) -> str:
    """Generate a cache key from function arguments."""
    key_data = {"args": args, "kwargs": sorted(kwargs.items())}
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    return hashlib.md5(key_str.encode()).hexdigest()


def cached(ttl: int = 300, use_redis: bool = True):
    """Decorator to cache function results."""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{func.__module__}.{func.__name__}:{cache_key(*args, **kwargs)}"

            # Try to get from cache
            cache = redis_cache if (use_redis and redis_cache) else memory_cache
            cached_result = cache.get(key)

            if cached_result is not None:
                log_performance_metric("cache_hit", 1, function=func.__name__)
                return cached_result

            # Execute function and cache result
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time

            cache.set(key, result, ttl)

            log_performance_metric("cache_miss", 1, function=func.__name__)
            log_performance_metric(
                "function_execution_time", execution_time, unit="seconds", function=func.__name__
            )

            return result

        return wrapper

    return decorator


def timed(func: F) -> F:
    """Decorator to measure function execution time."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            success = True
            return result
        except Exception:
            success = False
            raise
        finally:
            execution_time = time.time() - start_time
            log_performance_metric(
                "function_execution_time",
                execution_time,
                unit="seconds",
                function=func.__name__,
                success=success,
            )

    return wrapper


class ConnectionPool:
    """Database connection pool manager."""

    def __init__(self, database_url: str, pool_size: int = 10, max_overflow: int = 20):
        from sqlalchemy import create_engine

        self.engine = create_engine(
            database_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            pool_recycle=3600,  # Recycle connections every hour
        )

    def get_session(self) -> Session:
        """Get a database session from the pool."""
        from sqlalchemy.orm import sessionmaker

        SessionLocal = sessionmaker(bind=self.engine)
        return SessionLocal()

    @asynccontextmanager
    async def get_async_session(self):
        """Async context manager for database sessions."""
        session = self.get_session()
        try:
            yield session
        finally:
            session.close()


class BatchProcessor:
    """Utility for batch processing operations."""

    def __init__(self, batch_size: int = 100):
        self.batch_size = batch_size
        self.batch = []
        self.processor_func = None

    def set_processor(self, func: Callable[[list], None]) -> None:
        """Set the function to process batches."""
        self.processor_func = func

    def add(self, item: Any) -> None:
        """Add item to current batch."""
        self.batch.append(item)
        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        """Process current batch and clear it."""
        if self.batch and self.processor_func:
            start_time = time.time()
            self.processor_func(self.batch)
            processing_time = time.time() - start_time

            log_performance_metric(
                "batch_processing_time", processing_time, unit="seconds", batch_size=len(self.batch)
            )

            self.batch.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, max_tokens: int, refill_rate: float):
        self.max_tokens = max_tokens
        self.tokens = max_tokens
        self.refill_rate = refill_rate
        self.last_refill = time.time()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        tokens_to_add = (now - self.last_refill) * self.refill_rate
        self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
        self.last_refill = now

    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens."""
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    async def acquire_async(self, tokens: int = 1, timeout: float = 1.0) -> bool:
        """Async version of acquire with timeout."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.acquire(tokens):
                return True
            await asyncio.sleep(0.01)  # Small delay

        return False


# Global instances
connection_pool: ConnectionPool | None = None
default_rate_limiter = RateLimiter(max_tokens=100, refill_rate=10.0)


def init_connection_pool() -> None:
    """Initialize database connection pool."""
    global connection_pool
    connection_pool = ConnectionPool(settings.database_url)


def get_connection_pool() -> ConnectionPool:
    """Get the global connection pool."""
    if connection_pool is None:
        init_connection_pool()
    return connection_pool


logger = logging.getLogger(__name__)
