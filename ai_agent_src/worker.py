import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(message)s")
logger = logging.getLogger(__name__)

REDIS_URL      = os.getenv("REDIS_URL", "redis://redis:6379")
API_URL        = os.getenv("WORKER_API_URL", "http://ai-agent-api:8000")
API_KEY        = os.getenv("API_KEY", "").strip()
QUEUE_KEY      = "nexussoc:queue"
DLQ_KEY        = "nexussoc:dlq"
JOB_PREFIX     = "nexussoc:job:"
JOB_TTL        = 3600
LLM_TIMEOUT    = 180.0
MAX_RETRIES    = 3
HEARTBEAT_KEY  = "nexussoc:worker:heartbeat"
HEARTBEAT_TTL  = 120  # 2× the write interval


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _heartbeat(rc: aioredis.Redis) -> None:
    """Write a Unix timestamp to Redis every 30 s so /health can detect worker liveness."""
    while True:
        try:
            await rc.set(HEARTBEAT_KEY, str(time.time()), ex=HEARTBEAT_TTL)
        except Exception as exc:
            logger.warning("Heartbeat write failed: %s", exc)
        await asyncio.sleep(30)


async def process_job(rc: aioredis.Redis, job_id: str, alert: dict, attempt: int) -> None:
    await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
        "status":     "processing",
        "started_at": _now(),
        "attempt":    attempt,
    })
    try:
        headers = {"X-API-Key": API_KEY} if API_KEY else {}
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT, headers=headers) as client:
            resp = await client.post(f"{API_URL}/analyze-case", json=alert)
            resp.raise_for_status()
            result = resp.json()
        await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
            "status":       "done",
            "result":       json.dumps(result),
            "completed_at": _now(),
        })
        logger.info("job=%s case=%s attempt=%d decision=%s conf=%.0f%%",
                    job_id, alert.get("sourceRef", "?"), attempt,
                    result.get("result", {}).get("decision", "?"),
                    result.get("result", {}).get("confidence", 0) * 100)

    except Exception as exc:
        logger.error("job=%s attempt=%d/%d error=%s", job_id, attempt, MAX_RETRIES, exc)

        if attempt < MAX_RETRIES:
            backoff = 2 ** attempt  # 2s → 4s → 8s
            logger.info("job=%s retrying in %ds", job_id, backoff)
            await asyncio.sleep(backoff)
            next_payload = {**alert, "_job_id": job_id, "_attempt": attempt + 1}
            await rc.lpush(QUEUE_KEY, json.dumps(next_payload, default=str))
            await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
                "status":     "retrying",
                "last_error": str(exc)[:500],
            })
        else:
            dlq_entry = json.dumps({
                "job_id":     job_id,
                "alert":      alert,
                "attempts":   attempt,
                "last_error": str(exc)[:500],
                "failed_at":  _now(),
            }, default=str)
            await rc.lpush(DLQ_KEY, dlq_entry)
            await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
                "status":       "dead",
                "error":        str(exc)[:500],
                "completed_at": _now(),
            })
            logger.error("job=%s moved to DLQ after %d attempts", job_id, attempt)

    finally:
        await rc.expire(f"{JOB_PREFIX}{job_id}", JOB_TTL)


async def run_worker() -> None:
    rc = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Ready — queue=%s dlq=%s api=%s max_retries=%d",
                QUEUE_KEY, DLQ_KEY, API_URL, MAX_RETRIES)
    asyncio.create_task(_heartbeat(rc))
    while True:
        try:
            item = await rc.brpop(QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, payload = item
            data    = json.loads(payload)
            job_id  = data.pop("_job_id", str(uuid.uuid4()))
            attempt = data.pop("_attempt", 1)
            asyncio.create_task(process_job(rc, job_id, data, attempt))
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Queue loop error: %s", exc)
            await asyncio.sleep(2)
    await rc.aclose()


if __name__ == "__main__":
    asyncio.run(run_worker())
