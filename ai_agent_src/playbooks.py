import os
import logging
import json
from datetime import datetime, timezone
import httpx

logger = logging.getLogger(__name__)

# Set PLAYBOOK_DRY_RUN=true to log intended actions without executing real webhooks.
# Discord notifications still fire in dry-run mode.
# Flip to false (or remove) when real SOC stack is connected.
DRY_RUN = os.getenv("PLAYBOOK_DRY_RUN", "true").lower() == "true"


async def _run_action(action: dict, context: dict, client: httpx.AsyncClient) -> dict:
    """Execute one playbook action. Returns {type, status, detail}."""
    action_type = action.get("type", "log")

    if action_type == "log":
        msg = action.get("message", "Playbook executed for {case_id}").format(**context)
        logger.info(f"[PLAYBOOK] {msg}")
        return {"type": "log", "status": "ok", "detail": msg}

    if action_type == "discord":
        url = action.get("url") or context.get("discord_url", "")
        if not url:
            return {"type": "discord", "status": "skipped", "detail": "no webhook url"}
        msg = action.get("message", "Playbook triggered for {case_id}").format(**context)
        try:
            r = await client.post(url, json={"content": msg}, timeout=8.0)
            return {"type": "discord", "status": "ok" if r.status_code < 300 else "error", "detail": str(r.status_code)}
        except Exception as e:
            return {"type": "discord", "status": "error", "detail": str(e)}

    if action_type == "webhook":
        url = action.get("url", "")
        if not url:
            return {"type": "webhook", "status": "skipped", "detail": "no url"}
        method   = action.get("method", "POST").upper()
        payload  = action.get("payload", {})
        safe_ctx = {k: str(v) for k, v in context.items()}
        resolved = json.loads(json.dumps(payload).format(**safe_ctx))

        if DRY_RUN:
            detail = f"[DRY-RUN] would {method} {url} payload={json.dumps(resolved)[:120]}"
            logger.info(f"[PLAYBOOK DRY-RUN] {detail}")
            return {"type": "webhook", "status": "dry_run", "detail": detail}

        try:
            if method == "POST":
                r = await client.post(url, json=resolved, timeout=10.0)
            elif method == "GET":
                r = await client.get(url, params=resolved, timeout=10.0)
            else:
                r = await client.request(method, url, json=resolved, timeout=10.0)
            return {"type": "webhook", "status": "ok" if r.status_code < 300 else "error", "detail": str(r.status_code)}
        except Exception as e:
            return {"type": "webhook", "status": "error", "detail": str(e)}

    return {"type": action_type, "status": "unknown_type", "detail": f"unsupported: {action_type}"}


async def execute_playbooks(pool, alert, result: dict, discord_url: str = "") -> list[dict]:
    """
    Match enabled playbooks against alert+result, execute actions, log to DB.
    Silently skips if no playbooks match.
    """
    decision    = result.get("decision", "")
    confidence  = float(result.get("confidence", 0.0))
    attack_type = getattr(alert, "attack_type", None)

    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, name, actions
            FROM soc_playbooks
            WHERE enabled = TRUE
              AND trigger_decision = $1
              AND trigger_min_confidence <= $2
              AND (trigger_attack_types IS NULL OR $3 = ANY(trigger_attack_types))
            ORDER BY trigger_min_confidence DESC
        """, decision, confidence, attack_type)

    if not rows:
        return []

    context = {
        "case_id":     alert.sourceRef,
        "hostname":    getattr(alert, "hostname", "") or "",
        "source_ip":   (alert.network.source_ip if alert.network else "") or "",
        "decision":    decision,
        "confidence":  f"{confidence:.0%}",
        "attack_type": attack_type or "",
        "title":       alert.title,
        "discord_url": discord_url,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }

    summaries = []
    async with httpx.AsyncClient() as client:
        for row in rows:
            actions = row["actions"] if isinstance(row["actions"], list) else json.loads(row["actions"])
            action_results = []
            for action in actions:
                outcome = await _run_action(action, context, client)
                action_results.append(outcome)

            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO soc_playbook_executions
                        (case_id, playbook_id, playbook_name, actions_taken)
                    VALUES ($1, $2, $3, $4)
                """, alert.sourceRef, row["id"], row["name"], json.dumps(action_results))

                await conn.execute(
                    "UPDATE soc_playbooks SET execution_count = execution_count + 1 WHERE id = $1",
                    row["id"]
                )

            logger.info(f"Playbook '{row['name']}' → {alert.sourceRef} ({len(action_results)} actions)")
            summaries.append({"playbook": row["name"], "actions": action_results})

    return summaries
