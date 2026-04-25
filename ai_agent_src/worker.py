import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(message)s")
logger = logging.getLogger(__name__)

REDIS_URL   = os.getenv("REDIS_URL", "redis://redis:6379")
API_URL     = os.getenv("WORKER_API_URL", "http://ai-agent-api:8000")
QUEUE_KEY   = "nexussoc:queue"
JOB_PREFIX  = "nexussoc:job:"
JOB_TTL     = 3600   # results kept 1 hour
LLM_TIMEOUT = 180.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def process_job(rc: aioredis.Redis, job_id: str, alert: dict) -> None:
    await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={"status": "processing", "started_at": _now()})
    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            resp = await client.post(f"{API_URL}/analyze-case", json=alert)
            resp.raise_for_status()
            result = resp.json()
        await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
            "status":       "done",
            "result":       json.dumps(result),
            "completed_at": _now(),
        })
        logger.info("job=%s case=%s decision=%s conf=%.0f%%",
                    job_id, alert.get("case_id", "?"),
                    result.get("result", {}).get("decision", "?"),
                    result.get("result", {}).get("confidence", 0) * 100)
    except Exception as exc:
        await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
            "status":       "error",
            "error":        str(exc)[:500],
            "completed_at": _now(),
        })
        logger.error("job=%s error=%s", job_id, exc)
    finally:
        await rc.expire(f"{JOB_PREFIX}{job_id}", JOB_TTL)


async def run_worker() -> None:
    rc = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Ready — queue=%s  api=%s", QUEUE_KEY, API_URL)
    while True:
        try:
            item = await rc.brpop(QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, payload = item
            data   = json.loads(payload)
            job_id = data.pop("_job_id", str(uuid.uuid4()))
            asyncio.create_task(process_job(rc, job_id, data))
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Queue loop error: %s", exc)
            await asyncio.sleep(2)
    await rc.aclose()


if __name__ == "__main__":
    asyncio.run(run_worker())
