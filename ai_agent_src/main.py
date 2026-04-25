import os
import json
import re
import uuid
import httpx
import asyncpg
import asyncio
import logging
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from contextlib import asynccontextmanager
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum

from playbooks import execute_playbooks
from correlator import correlate_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── CONFIG ──────────────────────────────────────────────────────────────────

def load_config():
    required = ["DB_USER", "DB_PASS", "DB_NAME", "DB_HOST"]
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        raise ValueError(f"Missing env vars: {', '.join(missing)}")
    return {
        "db_user": os.getenv("DB_USER"),
        "db_pass": os.getenv("DB_PASS"),
        "db_name": os.getenv("DB_NAME"),
        "db_host": os.getenv("DB_HOST"),
        "db_port": int(os.getenv("DB_PORT", "5432")),
    }

try:
    CONFIG = load_config()
except ValueError as e:
    logger.error(str(e))
    raise

DISCORD_URL   = os.getenv("DISCORD_WEBHOOK", "").strip()
REDIS_URL     = os.getenv("REDIS_URL", "").strip()
QUEUE_KEY     = "nexussoc:queue"
JOB_PREFIX    = "nexussoc:job:"
JOB_TTL       = 3600
OLLAMA_HOST   = os.getenv("OLLAMA_HOST", "host.docker.internal")
OLLAMA_PORT   = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
EMBED_MODEL   = os.getenv("EMBED_MODEL", "nomic-embed-text")
OLLAMA_URL    = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate"
EMBED_URL     = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/embeddings"
EMBED_DIM     = 768

# Skill learning thresholds
SKILL_EXTRACT_MIN_CONFIDENCE = 0.85
SKILL_MATCH_MIN_SIMILARITY   = 0.78
MEMORY_MATCH_MIN_SIMILARITY  = 0.72
SKILL_EMA_ALPHA              = 0.15   # learning rate for confidence updates

logger.info(f"Model={OLLAMA_MODEL} | Embed={EMBED_MODEL} | DB={CONFIG['db_host']}")

# ── DB INIT ─────────────────────────────────────────────────────────────────

INIT_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS ai_analysis (
    id               SERIAL PRIMARY KEY,
    timestamp        TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    case_id          VARCHAR(100) NOT NULL,
    raw_alert        JSONB,
    ai_decision      VARCHAR(50),
    confidence       FLOAT,
    analysis_summary TEXT,
    recommended_action TEXT
);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS embedding vector({dim});

CREATE INDEX IF NOT EXISTS idx_case_id   ON ai_analysis(case_id);
CREATE INDEX IF NOT EXISTS idx_timestamp ON ai_analysis(timestamp);
CREATE INDEX IF NOT EXISTS idx_mem_embed ON ai_analysis
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;

CREATE TABLE IF NOT EXISTS soc_skills (
    id               SERIAL PRIMARY KEY,
    created_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    skill_name       VARCHAR(200) NOT NULL,
    pattern          TEXT NOT NULL,
    decision         VARCHAR(50),
    embedding        vector({dim}),
    confidence_score FLOAT DEFAULT 0.70,
    usage_count      INT   DEFAULT 0,
    success_count    INT   DEFAULT 0,
    mitre_techniques TEXT[]
);
CREATE INDEX IF NOT EXISTS idx_skill_embed ON soc_skills
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;

CREATE TABLE IF NOT EXISTS soc_playbooks (
    id                     SERIAL PRIMARY KEY,
    created_at             TIMESTAMPTZ DEFAULT NOW(),
    name                   VARCHAR(200) NOT NULL,
    description            TEXT,
    trigger_decision       VARCHAR(50)  NOT NULL DEFAULT 'True Positive',
    trigger_min_confidence FLOAT        NOT NULL DEFAULT 0.85,
    trigger_attack_types   TEXT[],
    actions                JSONB        NOT NULL DEFAULT '[]',
    enabled                BOOLEAN      NOT NULL DEFAULT TRUE,
    execution_count        INT          NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS soc_playbook_executions (
    id            SERIAL PRIMARY KEY,
    executed_at   TIMESTAMPTZ DEFAULT NOW(),
    case_id       VARCHAR(100) NOT NULL,
    playbook_id   INT REFERENCES soc_playbooks(id) ON DELETE SET NULL,
    playbook_name VARCHAR(200),
    actions_taken JSONB
);
CREATE INDEX IF NOT EXISTS idx_pb_exec_case ON soc_playbook_executions(case_id);

CREATE TABLE IF NOT EXISTS soc_incidents (
    id                SERIAL PRIMARY KEY,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    incident_id       VARCHAR(100) UNIQUE NOT NULL,
    title             TEXT,
    status            VARCHAR(50)  NOT NULL DEFAULT 'open',
    severity          VARCHAR(50)  NOT NULL DEFAULT 'medium',
    case_ids          TEXT[]       NOT NULL DEFAULT '{{}}',
    kill_chain_phases TEXT[]       NOT NULL DEFAULT '{{}}',
    source_ips        TEXT[]       NOT NULL DEFAULT '{{}}',
    hostnames         TEXT[]       NOT NULL DEFAULT '{{}}',
    users             TEXT[]       NOT NULL DEFAULT '{{}}',
    attack_types      TEXT[]       NOT NULL DEFAULT '{{}}',
    mitre_techniques  TEXT[]       NOT NULL DEFAULT '{{}}',
    case_count        INT          NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_inc_status  ON soc_incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_updated ON soc_incidents(updated_at);
""".format(dim=EMBED_DIM)

# ── LIFESPAN ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    app.state.db_pool = await asyncpg.create_pool(
        user=CONFIG["db_user"], password=CONFIG["db_pass"],
        database=CONFIG["db_name"], host=CONFIG["db_host"],
        port=CONFIG["db_port"], min_size=5, max_size=20
    )
    async with app.state.db_pool.acquire() as conn:
        await conn.execute(INIT_SQL)
    logger.info("DB ready with pgvector + skills tables")
    if REDIS_URL:
        app.state.redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        logger.info("Redis queue ready: %s", REDIS_URL)
    else:
        app.state.redis = None
        logger.info("Redis not configured — async ingest disabled")
    yield
    await app.state.db_pool.close()
    if app.state.redis:
        await app.state.redis.aclose()

# ── APP ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SOC AI Agent",
    description="AI-powered SOC analyst with memory, pgvector similarity, and self-updating skills",
    version="2.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ENUMS ─────────────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class AlertSource(str, Enum):
    SURICATA_IDS    = "Suricata IDS"
    SPLUNK_DLP      = "Splunk DLP"
    EDR             = "Endpoint Detection and Response (EDR)"
    NETFLOW         = "NetFlow Analysis"
    WINDOWS_EVENTS  = "Windows Event Logs + Sigma Rules"
    SIEM            = "SIEM"
    WAF             = "Web Application Firewall"

class AttackType(str, Enum):
    BRUTE_FORCE          = "brute_force"
    DATA_EXFILTRATION    = "data_exfiltration"
    MALWARE              = "malware"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT     = "lateral_movement"
    RECONNAISSANCE       = "reconnaissance"
    DOS                  = "denial_of_service"
    UNKNOWN              = "unknown"

# ── REQUEST / RESPONSE MODELS ─────────────────────────────────────────────────

class NetworkIndicators(BaseModel):
    source_ip:      Optional[str]  = None
    destination_ip: Optional[str]  = None
    protocol:       Optional[str]  = None
    port:           Optional[int]  = Field(None, ge=1, le=65535)
    tor_exit_node:  Optional[bool] = False

class FileAnalysis(BaseModel):
    file_name:        Optional[str]       = None
    file_hash_md5:    Optional[str]       = Field(None, pattern=r'^[a-fA-F0-9]{32}$')
    file_hash_sha256: Optional[str]       = Field(None, pattern=r'^[a-fA-F0-9]{64}$')
    file_size_bytes:  Optional[int]       = Field(None, ge=0)
    yara_rule:        Optional[str]       = None
    av_detections:    Optional[List[str]] = None
    process_behavior: Optional[List[str]] = None
    c2_infrastructure:Optional[str]       = None

class DataExfiltrationDetails(BaseModel):
    data_volume_gb: Optional[float]      = Field(None, ge=0)
    data_types:     Optional[List[str]]  = None
    transfer_type:  Optional[str]        = None
    encryption:     Optional[str]        = None
    dlp_rule:       Optional[str]        = None

class PrivilegeEscalationDetails(BaseModel):
    privilege_level_before:    Optional[str]       = None
    privilege_level_after:     Optional[str]       = None
    exploit_cve:               Optional[str]       = None
    process_chain:             Optional[List[str]] = None
    sigma_rules_triggered:     Optional[List[str]] = None
    credential_spray_detected: Optional[bool]      = False

class SecurityAlert(BaseModel):
    sourceRef:         str            = Field(..., min_length=1, max_length=100)
    thehive_id:        Optional[str]  = None
    title:             str            = Field(..., min_length=5, max_length=500)
    description:       str            = Field(..., min_length=10, max_length=10000)
    source:            Optional[AlertSource]   = None
    severity:          Optional[SeverityLevel] = "medium"
    timestamp:         Optional[str]  = None
    attack_type:       Optional[AttackType] = None
    indicators:        Optional[List[str]] = None
    user:              Optional[str]  = None
    hostname:          Optional[str]  = None
    network:           Optional[NetworkIndicators]       = None
    file_analysis:     Optional[FileAnalysis]            = None
    event_count:       Optional[int]  = Field(None, ge=0)
    time_window_seconds: Optional[int] = Field(None, ge=0)
    data_exfil:        Optional[DataExfiltrationDetails] = None
    priv_esc:          Optional[PrivilegeEscalationDetails] = None
    is_scheduled:      Optional[bool] = False
    scheduled_task:    Optional[str]  = None
    frequency:         Optional[str]  = None
    time_of_day:       Optional[str]  = None
    mitre_techniques:  Optional[List[str]] = Field(None, description="MITRE ATT&CK IDs e.g. T1059.001")
    correlated_cases:  Optional[List[str]] = Field(None, description="Related case IDs in same chain")
    kill_chain_phase:  Optional[str]  = Field(None, description="recon/delivery/exploit/install/c2/lateral/exfil/actions")
    # Pre-enriched by upstream SOC infra (AbuseIPDB + VirusTotal)
    ip_abuse_score:    Optional[int]       = Field(None, ge=0, le=100, description="AbuseIPDB confidence score 0-100")
    ip_is_tor:         Optional[bool]      = None
    ip_total_reports:  Optional[int]       = Field(None, ge=0)
    vt_malicious:      Optional[int]       = Field(None, ge=0, description="VirusTotal malicious engine count")
    vt_total:          Optional[int]       = Field(None, ge=0, description="VirusTotal total engines scanned")
    vt_names:          Optional[List[str]] = Field(None, description="Known malware names from VirusTotal")

    class Config:
        use_enum_values = True

    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v:
            try:
                datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError('Invalid ISO 8601 timestamp')
        return v

class FeedbackRequest(BaseModel):
    correct:      bool
    analyst_note: Optional[str] = None

# ── EMBEDDING ─────────────────────────────────────────────────────────────────

async def get_embedding(text: str) -> Optional[List[float]]:
    """Get 768-dim embedding from Ollama nomic-embed-text."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(EMBED_URL, json={"model": EMBED_MODEL, "prompt": text[:2000]})
            if r.status_code == 200:
                return r.json().get("embedding")
    except Exception as e:
        logger.warning(f"Embedding failed: {e}")
    return None

def _alert_to_text(alert: SecurityAlert) -> str:
    """Flatten alert to a single string for embedding."""
    parts = [alert.title, alert.description]
    if alert.attack_type:    parts.append(f"attack:{alert.attack_type}")
    if alert.mitre_techniques: parts.extend(alert.mitre_techniques)
    if alert.indicators:     parts.extend(alert.indicators)
    if alert.kill_chain_phase: parts.append(f"phase:{alert.kill_chain_phase}")
    if alert.hostname:       parts.append(f"host:{alert.hostname}")
    return " | ".join(parts)

# ── MEMORY: similar past cases ────────────────────────────────────────────────

async def find_similar_memories(pool, embedding: List[float], limit: int = 3) -> List[dict]:
    """Find top-K past cases by cosine similarity."""
    vec_str = "[" + ",".join(str(x) for x in embedding) + "]"
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT case_id, ai_decision, confidence, analysis_summary,
                   1 - (embedding <=> '{vec_str}'::vector) AS similarity
            FROM ai_analysis
            WHERE embedding IS NOT NULL
              AND 1 - (embedding <=> '{vec_str}'::vector) > {MEMORY_MATCH_MIN_SIMILARITY}
            ORDER BY embedding <=> '{vec_str}'::vector
            LIMIT {limit}
        """)
    return [dict(r) for r in rows]

# ── SKILLS: retrieve + save + update ─────────────────────────────────────────

async def find_relevant_skills(pool, embedding: List[float], limit: int = 5) -> List[dict]:
    """Find top-K skills by cosine similarity, filtered by confidence."""
    vec_str = "[" + ",".join(str(x) for x in embedding) + "]"
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT id, skill_name, pattern, decision, confidence_score, usage_count, mitre_techniques,
                   1 - (embedding <=> '{vec_str}'::vector) AS similarity
            FROM soc_skills
            WHERE embedding IS NOT NULL
              AND confidence_score > 0.40
              AND 1 - (embedding <=> '{vec_str}'::vector) > {SKILL_MATCH_MIN_SIMILARITY}
            ORDER BY embedding <=> '{vec_str}'::vector
            LIMIT {limit}
        """)
    return [dict(r) for r in rows]

async def update_skill_usage(pool, skill_ids: List[int]):
    """Increment usage count for retrieved skills."""
    if not skill_ids:
        return
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE soc_skills SET usage_count = usage_count + 1, updated_at = NOW() WHERE id = ANY($1)",
            skill_ids
        )

async def extract_and_save_skill(pool, alert: SecurityAlert, result: dict, embedding: List[float]):
    """Background task: ask LLM to extract a reusable detection skill, then save it."""
    try:
        skill_prompt = f"""[INST] You are a senior threat intelligence analyst.
Extract a concise, reusable detection skill from this SOC analysis.

Alert title: {alert.title}
Attack type: {alert.attack_type}
Kill chain phase: {alert.kill_chain_phase}
MITRE techniques: {', '.join(alert.mitre_techniques or [])}
Decision: {result['decision']}
Confidence: {result['confidence']}
Reasoning: {result.get('explanation', '')[:300]}

Write a short, generalizable detection pattern a SOC analyst can reuse on future alerts.
Respond ONLY with valid JSON:
{{"skill_name": "short name", "pattern": "generalizable detection rule in 1-2 sentences", "mitre_techniques": ["T1xxx"]}}
[/INST]"""

        skill_result = await query_ollama(skill_prompt, timeout=180)
        skill_name = skill_result.get("skill_name", f"Skill from {alert.attack_type}")
        pattern    = skill_result.get("pattern", result.get("explanation", "")[:300])
        mitre      = skill_result.get("mitre_techniques", alert.mitre_techniques or [])

        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO soc_skills
                    (skill_name, pattern, decision, embedding, confidence_score, mitre_techniques)
                VALUES ($1, $2, $3, $4::vector, $5, $6)
            """,
                skill_name, pattern, result['decision'],
                "[" + ",".join(str(x) for x in embedding) + "]",
                result['confidence'], mitre
            )
        logger.info(f"Skill extracted: '{skill_name}'")

    except Exception as e:
        logger.warning(f"Skill extraction failed: {e}")

async def update_skill_feedback(pool, case_id: str, correct: bool):
    """EMA update on skills that influenced this case's analysis."""
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT embedding FROM ai_analysis WHERE case_id = $1 ORDER BY timestamp DESC LIMIT 1",
                case_id
            )
            if not row or not row['embedding']:
                return

            emb = row['embedding']
            vec_str = emb if isinstance(emb, str) else ("[" + ",".join(str(x) for x in emb) + "]")
            skills = await conn.fetch(f"""
                SELECT id, confidence_score, success_count, usage_count
                FROM soc_skills
                WHERE embedding IS NOT NULL
                  AND 1 - (embedding <=> '{vec_str}'::vector) > {SKILL_MATCH_MIN_SIMILARITY}
                LIMIT 5
            """)

            for s in skills:
                old_conf = s['confidence_score']
                # EMA: nudge confidence toward 1.0 (correct) or 0.0 (wrong)
                target = 1.0 if correct else 0.0
                new_conf = old_conf + SKILL_EMA_ALPHA * (target - old_conf)
                new_conf = max(0.05, min(0.99, new_conf))
                new_success = s['success_count'] + (1 if correct else 0)

                await conn.execute("""
                    UPDATE soc_skills
                    SET confidence_score = $1, success_count = $2, updated_at = NOW()
                    WHERE id = $3
                """, new_conf, new_success, s['id'])

            logger.info(f"Updated {len(skills)} skills from feedback on {case_id} (correct={correct})")

    except Exception as e:
        logger.warning(f"Skill feedback update failed: {e}")

# ── OLLAMA ────────────────────────────────────────────────────────────────────

async def query_ollama(prompt: str, timeout: int = 300) -> dict:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                OLLAMA_URL,
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json", "think": False}
            )
            if r.status_code != 200:
                raise HTTPException(status_code=r.status_code, detail=f"Ollama error: {r.text[:200]}")
            raw = r.json().get("response", "")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', raw, re.DOTALL)
                if match:
                    return json.loads(match.group())
                raise ValueError("Could not parse JSON from Ollama")
    except httpx.ReadTimeout:
        raise HTTPException(status_code=504, detail=f"Ollama timeout. Model loaded? ollama pull {OLLAMA_MODEL}")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Cannot reach Ollama. Run: ollama serve")

# ── DISCORD ───────────────────────────────────────────────────────────────────

async def send_to_discord(case_id, title, confidence, explanation, decision="True Positive", recommended_action=""):
    if not DISCORD_URL:
        return
    is_tp = decision == "True Positive"
    embed_title  = "🚨 TRUE POSITIVE — THREAT CONFIRMED" if is_tp else "✅ FALSE POSITIVE — NO ACTION REQUIRED"
    embed_color  = 15158332 if is_tp else 3066993  # red : green
    decision_val = f"⚡ {decision}" if is_tp else f"✓ {decision}"
    fields = [
        {"name": "Case",       "value": str(case_id),                  "inline": True},
        {"name": "Decision",   "value": decision_val,                   "inline": True},
        {"name": "Confidence", "value": f"{round(confidence*100,1)}%",  "inline": True},
        {"name": "Summary",    "value": explanation[:1000]},
    ]
    if recommended_action:
        fields.append({"name": "→ Recommended Action", "value": recommended_action[:512]})
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(DISCORD_URL, json={"embeds": [{"title": embed_title, "color": embed_color, "fields": fields}]})
    except Exception as e:
        logger.error(f"Discord error: {e}")

# ── BUILD PROMPT ──────────────────────────────────────────────────────────────

def build_prompt(alert: SecurityAlert, memories: List[dict], skills: List[dict]) -> str:
    alert_lines = [
        f"Title: {alert.title}",
        f"Description: {alert.description[:600]}",
        f"Severity: {alert.severity}",
        f"Attack Type: {alert.attack_type}",
        f"Kill Chain Phase: {alert.kill_chain_phase or 'unknown'}",
    ]
    if alert.mitre_techniques:
        alert_lines.append(f"MITRE ATT&CK: {', '.join(alert.mitre_techniques)}")
    if alert.indicators:
        alert_lines.append(f"Indicators: {', '.join(alert.indicators)}")
    if alert.correlated_cases:
        alert_lines.append(f"Correlated Cases: {' → '.join(alert.correlated_cases)}")
    if alert.network:
        n = alert.network
        alert_lines.append(f"Network: src={n.source_ip} dst={n.destination_ip} proto={n.protocol} tor={n.tor_exit_node}")
    if alert.file_analysis:
        f = alert.file_analysis
        alert_lines.append(f"File: {f.file_name} yara={f.yara_rule} c2={f.c2_infrastructure}")
    if alert.data_exfil:
        d = alert.data_exfil
        alert_lines.append(f"Exfil: {d.data_volume_gb}GB types={d.data_types} rule={d.dlp_rule}")
    if alert.priv_esc:
        p = alert.priv_esc
        alert_lines.append(f"PrivEsc: {p.privilege_level_before}→{p.privilege_level_after} cve={p.exploit_cve}")
    if alert.is_scheduled:
        alert_lines.append(f"Scheduled: {alert.scheduled_task} freq={alert.frequency}")
    if alert.user:
        alert_lines.append(f"User: {alert.user}  Host: {alert.hostname}")

    enrichment_block = ""
    enrichment_lines = []
    if alert.ip_abuse_score is not None:
        enrichment_lines.append(
            f"  IP abuse_score={alert.ip_abuse_score}% "
            f"reports={alert.ip_total_reports} tor={alert.ip_is_tor}"
        )
    if alert.vt_malicious is not None:
        vt_ratio = f"{alert.vt_malicious}/{alert.vt_total}" if alert.vt_total else str(alert.vt_malicious)
        enrichment_lines.append(
            f"  File malicious={vt_ratio} engines names={alert.vt_names}"
        )
    if enrichment_lines:
        enrichment_block = "\n--- THREAT INTEL ENRICHMENT ---\n" + "\n".join(enrichment_lines)

    memory_block = ""
    if memories:
        lines = [f"\n--- SIMILAR PAST CASES (from agent memory) ---"]
        for m in memories:
            lines.append(
                f"  [{m['case_id']}] Decision={m['ai_decision']} "
                f"Confidence={m['confidence']:.0%} similarity={m['similarity']:.0%}\n"
                f"  Summary: {(m['analysis_summary'] or '')[:120]}"
            )
        memory_block = "\n".join(lines)

    skill_block = ""
    if skills:
        lines = [f"\n--- LEARNED SKILLS (from agent experience) ---"]
        for s in skills:
            lines.append(
                f"  [{s['skill_name']}] expected={s['decision']} "
                f"skill_confidence={s['confidence_score']:.0%} used={s['usage_count']}x\n"
                f"  Pattern: {s['pattern'][:150]}"
            )
        skill_block = "\n".join(lines)

    return f"""[INST] You are a senior SOC analyst with expertise in threat hunting and incident response.
Analyze this security alert. Use the memory context and learned skills below to improve accuracy.
For scheduled/authorized/legitimate activities, lean toward False Positive.
For multi-stage attacks with correlated cases or matching skills, weigh the full evidence.

=== CURRENT ALERT ===
{chr(10).join(alert_lines)}
{enrichment_block}
{memory_block}
{skill_block}

=== CONFIDENCE CALIBRATION GUIDE ===
Be conservative. Real SOC analysts rarely exceed 0.90 without multiple corroborating sources.
0.90-1.00 : Multiple IOCs confirmed + matching learned skill + threat intel enrichment all agree
0.75-0.89 : Strong indicators but missing one corroborating source (no enrichment OR no skill match)
0.60-0.74 : Suspicious activity, limited context, single indicator only
0.40-0.59 : Ambiguous — could be benign or malicious, needs human review
0.00-0.39 : Likely benign / insufficient evidence to decide

Respond with ONLY valid JSON (no extra text):
{{"decision": "True Positive" or "False Positive", "confidence": 0.0-1.0, "explanation": "reasoning under 200 words", "recommended_action": "triage action"}}
[/INST]"""

# ── ENDPOINTS ─────────────────────────────────────────────────────────────────

@app.post("/analyze-case")
async def analyze_case(alert: SecurityAlert, background_tasks: BackgroundTasks):
    case_id = alert.sourceRef
    logger.info(f"Analyzing: {case_id}")

    # 1. Embed the alert
    alert_text = _alert_to_text(alert)
    embedding  = await get_embedding(alert_text)

    # 2. Retrieve memory + skills in parallel
    memories, skills = [], []
    if embedding:
        memories, skills = await asyncio.gather(
            find_similar_memories(app.state.db_pool, embedding),
            find_relevant_skills(app.state.db_pool, embedding)
        )
        if skills:
            skill_ids = [s['id'] for s in skills]
            background_tasks.add_task(update_skill_usage, app.state.db_pool, skill_ids)

    logger.info(f"Context: {len(memories)} memories, {len(skills)} skills")

    # 3. Build prompt and query AI
    prompt = build_prompt(alert, memories, skills)
    result = await query_ollama(prompt, timeout=300)

    if not all(k in result for k in ['decision', 'confidence', 'explanation']):
        raise HTTPException(status_code=500, detail="Invalid AI response structure")

    result['confidence'] = max(0.0, min(1.0, float(result['confidence'])))

    # Evidence-based ceiling: cap confidence to what the available context can support.
    # Without corroborating sources the LLM cannot legitimately be >0.90.
    has_enrichment = bool(alert.ip_abuse_score is not None or alert.vt_malicious is not None)
    has_skills     = bool(skills)
    has_memories   = bool(memories)
    if not has_enrichment and not has_skills:
        result['confidence'] = min(result['confidence'], 0.74)
    elif not has_enrichment or not has_skills:
        result['confidence'] = min(result['confidence'], 0.88)

    result.setdefault('recommended_action', 'Manual triage required')

    # 4. Save to DB with embedding
    vec_sql = ("'[" + ",".join(str(x) for x in embedding) + "]'::vector") if embedding else "NULL"
    async with app.state.db_pool.acquire() as conn:
        await conn.execute(f"""
            INSERT INTO ai_analysis
                (case_id, raw_alert, ai_decision, confidence, analysis_summary, recommended_action, embedding)
            VALUES ($1, $2, $3, $4, $5, $6, {vec_sql})
        """,
            case_id, json.dumps(alert.dict()),
            result['decision'], result['confidence'],
            result['explanation'], result['recommended_action']
        )

    # 5. Correlate alert → incidents
    incident_info = await correlate_alert(app.state.db_pool, alert, result, embedding)

    # 6. Background: extract skill if high-confidence
    if embedding and result['confidence'] >= SKILL_EXTRACT_MIN_CONFIDENCE:
        background_tasks.add_task(extract_and_save_skill, app.state.db_pool, alert, result, embedding)

    # 6. Execute matching playbooks
    playbook_summaries = []
    if result['decision'].lower() == "true positive":
        playbook_summaries = await execute_playbooks(
            app.state.db_pool, alert, result, discord_url=DISCORD_URL
        )

    # 7. Discord alert for critical true positives (fallback if no playbook covers it)
    if result['decision'].lower() == "true positive" and result['confidence'] >= 0.90:
        pb_has_discord = any(
            any(a.get("type") == "discord" for a in pb.get("actions", []))
            for pb in playbook_summaries
        )
        if not pb_has_discord:
            background_tasks.add_task(
                send_to_discord, case_id, alert.title,
                result['confidence'], result['explanation'],
                result.get('decision', 'True Positive'),
                result.get('recommended_action', '')
            )

    return {
        "status": "analyzed",
        "case_id": case_id,
        "memory_context": len(memories),
        "skills_applied": len(skills),
        "playbooks_executed": len(playbook_summaries),
        "incident": incident_info,
        "result": result
    }


@app.post("/feedback/{case_id}")
async def feedback(case_id: str, body: FeedbackRequest, background_tasks: BackgroundTasks):
    """Analyst confirms or denies the agent's decision — updates skill confidence via EMA."""
    async with app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, ai_decision, confidence FROM ai_analysis WHERE case_id = $1 ORDER BY timestamp DESC LIMIT 1",
            case_id
        )
    if not row:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    background_tasks.add_task(update_skill_feedback, app.state.db_pool, case_id, body.correct)

    return {
        "case_id":      case_id,
        "original_decision": row['ai_decision'],
        "analyst_verdict":   "correct" if body.correct else "incorrect",
        "skill_update":      "EMA update queued for relevant skills",
        "note":              body.analyst_note
    }


@app.get("/skills")
async def list_skills(min_confidence: float = 0.0, limit: int = 50):
    """List all learned skills, optionally filtered by confidence."""
    async with app.state.db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, skill_name, pattern, decision, confidence_score,
                   usage_count, success_count, mitre_techniques, created_at, updated_at
            FROM soc_skills
            WHERE confidence_score >= $1
            ORDER BY confidence_score DESC, usage_count DESC
            LIMIT $2
        """, min_confidence, limit)
    return {
        "total": len(rows),
        "skills": [dict(r) for r in rows]
    }


@app.delete("/skills/{skill_id}")
async def delete_skill(skill_id: int):
    """Remove a skill that is consistently wrong or irrelevant."""
    async with app.state.db_pool.acquire() as conn:
        result = await conn.execute("DELETE FROM soc_skills WHERE id = $1", skill_id)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail=f"Skill {skill_id} not found")
    return {"deleted": skill_id}


class SkillFeedbackRequest(BaseModel):
    correct: bool
    analyst_note: Optional[str] = None


@app.post("/skills/{skill_id}/feedback")
async def skill_feedback(skill_id: int, body: SkillFeedbackRequest):
    """Directly rate a skill pattern — applies EMA to confidence_score."""
    async with app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, skill_name, confidence_score, success_count, usage_count FROM soc_skills WHERE id = $1",
            skill_id
        )
        if not row:
            raise HTTPException(status_code=404, detail=f"Skill {skill_id} not found")

        old_conf    = row['confidence_score']
        target      = 1.0 if body.correct else 0.0
        new_conf    = old_conf + SKILL_EMA_ALPHA * (target - old_conf)
        new_conf    = max(0.05, min(0.99, new_conf))
        new_success = row['success_count'] + (1 if body.correct else 0)
        new_usage   = row['usage_count'] + 1

        await conn.execute("""
            UPDATE soc_skills
            SET confidence_score = $1, success_count = $2, usage_count = $3, updated_at = NOW()
            WHERE id = $4
        """, new_conf, new_success, new_usage, skill_id)

    logger.info(f"Skill {skill_id} feedback correct={body.correct} conf {old_conf:.3f} → {new_conf:.3f}")
    return {
        "skill_id":        skill_id,
        "skill_name":      row['skill_name'],
        "analyst_verdict": "correct" if body.correct else "incorrect",
        "confidence_before": round(old_conf, 4),
        "confidence_after":  round(new_conf, 4),
        "note":            body.analyst_note,
    }


@app.get("/memory")
async def get_memory(limit: int = 20):
    """View recent case memories stored by the agent."""
    async with app.state.db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT case_id, ai_decision, confidence, analysis_summary,
                   recommended_action, timestamp,
                   (embedding IS NOT NULL) AS has_embedding
            FROM ai_analysis
            ORDER BY timestamp DESC
            LIMIT $1
        """, limit)
    return {"total": len(rows), "memories": [dict(r) for r in rows]}


# ── ASYNC INGEST (queue-backed) ───────────────────────────────────────────────

@app.post("/ingest", status_code=202)
async def ingest_alert(alert: SecurityAlert, request: Request):
    rc = request.app.state.redis
    if not rc:
        raise HTTPException(status_code=503, detail="Queue unavailable — REDIS_URL not configured")
    job_id    = str(uuid.uuid4())
    case_id   = alert.case_id or job_id
    payload   = json.loads(alert.json())
    payload["_job_id"]   = job_id
    payload["timestamp"] = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
    await rc.hset(f"{JOB_PREFIX}{job_id}", mapping={
        "status":     "queued",
        "case_id":    case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await rc.expire(f"{JOB_PREFIX}{job_id}", JOB_TTL)
    await rc.lpush(QUEUE_KEY, json.dumps(payload, default=str))
    logger.info("Queued job=%s case=%s", job_id, case_id)
    return {"job_id": job_id, "case_id": case_id, "status": "queued"}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    rc = request.app.state.redis
    if not rc:
        raise HTTPException(status_code=503, detail="Queue unavailable — REDIS_URL not configured")
    data = await rc.hgetall(f"{JOB_PREFIX}{job_id}")
    if not data:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    if "result" in data:
        data["result"] = json.loads(data["result"])
    return data


@app.get("/queue/depth")
async def queue_depth(request: Request):
    rc = request.app.state.redis
    if not rc:
        return {"depth": 0, "redis": False}
    depth = await rc.llen(QUEUE_KEY)
    return {"depth": depth, "redis": True, "queue": QUEUE_KEY}


@app.get("/health")
async def health():
    db_status = "disconnected"
    skill_count = 0
    memory_count = 0
    try:
        async with app.state.db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
            skill_count  = await conn.fetchval("SELECT COUNT(*) FROM soc_skills")
            memory_count = await conn.fetchval("SELECT COUNT(*) FROM ai_analysis WHERE embedding IS NOT NULL")
        db_status = "connected"
    except Exception as e:
        logger.error(f"Health check failed: {e}")
    return {
        "status":           "healthy" if db_status == "connected" else "unhealthy",
        "database":         db_status,
        "ollama_model":     OLLAMA_MODEL,
        "embed_model":      EMBED_MODEL,
        "skills_learned":   skill_count,
        "memories_indexed": memory_count,
        "playbook_mode":    "dry_run" if os.getenv("PLAYBOOK_DRY_RUN", "true").lower() == "true" else "live",
    }


@app.get("/mitre/export")
async def mitre_export():
    """Export MITRE ATT&CK Navigator layer from all learned skills + analyzed cases."""
    async with app.state.db_pool.acquire() as conn:
        skill_rows = await conn.fetch("""
            SELECT mitre_techniques, confidence_score, usage_count
            FROM soc_skills
            WHERE mitre_techniques IS NOT NULL AND array_length(mitre_techniques, 1) > 0
        """)
        alert_rows = await conn.fetch("""
            SELECT raw_alert->>'mitre_techniques' AS techniques, confidence
            FROM ai_analysis
            WHERE raw_alert ? 'mitre_techniques'
              AND raw_alert->>'mitre_techniques' IS NOT NULL
        """)

    # Aggregate: technique_id -> {total_score, count}
    scores: dict[str, dict] = {}

    for row in skill_rows:
        for tech in (row["mitre_techniques"] or []):
            tid = tech.strip().upper()
            if not tid:
                continue
            entry = scores.setdefault(tid, {"score_sum": 0.0, "count": 0, "sources": []})
            entry["score_sum"] += float(row["confidence_score"] or 0) * 100
            entry["count"]     += max(1, int(row["usage_count"] or 1))
            entry["sources"].append(f"skill(conf={row['confidence_score']:.0%})")

    for row in alert_rows:
        try:
            techs = json.loads(row["techniques"] or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        for tech in techs:
            tid = tech.strip().upper()
            if not tid:
                continue
            entry = scores.setdefault(tid, {"score_sum": 0.0, "count": 0, "sources": []})
            entry["score_sum"] += float(row["confidence"] or 0) * 100
            entry["count"]     += 1

    techniques = []
    for tid, data in scores.items():
        avg_score = int(data["score_sum"] / max(data["count"], 1))
        techniques.append({
            "techniqueID":          tid,
            "score":                avg_score,
            "color":                "",
            "comment":              f"Seen {data['count']}x | avg score {avg_score}",
            "enabled":              True,
            "metadata":             [],
            "links":                [],
            "showSubtechniques":    False,
        })

    layer = {
        "name":        "NexusSoc Threat Detections",
        "versions":    {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": f"Auto-generated by NexusSoc — {len(techniques)} techniques detected",
        "filters":     {"platforms": ["Windows","Linux","macOS","Network","Cloud"]},
        "sorting":     3,
        "layout":      {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques":  techniques,
        "gradient":    {
            "colors":   ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems":                    [],
        "metadata":                       [],
        "showTacticRowBackground":        False,
        "tacticRowBackground":            "#dddddd",
        "selectTechniquesAcrossTactics":  True,
        "selectSubtechniquesWithParent":  False,
    }

    from fastapi.responses import Response
    return Response(
        content=json.dumps(layer, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=nexussoc-navigator.json"},
    )


@app.get("/incidents")
async def list_incidents(status: Optional[str] = None, limit: int = 20):
    async with app.state.db_pool.acquire() as conn:
        if status:
            rows = await conn.fetch("""
                SELECT incident_id, title, status, severity, case_count,
                       kill_chain_phases, attack_types, source_ips, hostnames,
                       created_at, updated_at
                FROM soc_incidents WHERE status = $1
                ORDER BY updated_at DESC LIMIT $2
            """, status, limit)
        else:
            rows = await conn.fetch("""
                SELECT incident_id, title, status, severity, case_count,
                       kill_chain_phases, attack_types, source_ips, hostnames,
                       created_at, updated_at
                FROM soc_incidents
                ORDER BY updated_at DESC LIMIT $1
            """, limit)
    return {"total": len(rows), "incidents": [dict(r) for r in rows]}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    async with app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM soc_incidents WHERE incident_id = $1", incident_id
        )
    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return dict(row)


@app.patch("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str):
    valid = {"open", "investigating", "closed"}
    if status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    async with app.state.db_pool.acquire() as conn:
        r = await conn.execute("""
            UPDATE soc_incidents SET status = $1, updated_at = NOW()
            WHERE incident_id = $2
        """, status, incident_id)
    if r == "UPDATE 0":
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return {"incident_id": incident_id, "status": status}


class PlaybookCreate(BaseModel):
    name:                   str
    description:            Optional[str]       = None
    trigger_decision:       str                 = "True Positive"
    trigger_min_confidence: float               = Field(0.85, ge=0.0, le=1.0)
    trigger_attack_types:   Optional[List[str]] = None
    actions:                List[dict]          = []
    enabled:                bool                = True


@app.get("/playbooks")
async def list_playbooks():
    async with app.state.db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, name, description, trigger_decision, trigger_min_confidence,
                   trigger_attack_types, actions, enabled, execution_count, created_at
            FROM soc_playbooks ORDER BY created_at DESC
        """)
    playbooks = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("actions"), str):
            d["actions"] = json.loads(d["actions"])
        playbooks.append(d)
    return {"total": len(playbooks), "playbooks": playbooks}


@app.post("/playbooks", status_code=201)
async def create_playbook(pb: PlaybookCreate):
    async with app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO soc_playbooks
                (name, description, trigger_decision, trigger_min_confidence,
                 trigger_attack_types, actions, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, name, trigger_decision, trigger_min_confidence, enabled
        """,
            pb.name, pb.description, pb.trigger_decision, pb.trigger_min_confidence,
            pb.trigger_attack_types, json.dumps(pb.actions), pb.enabled
        )
    return {"created": dict(row)}


@app.delete("/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: int):
    async with app.state.db_pool.acquire() as conn:
        r = await conn.execute("DELETE FROM soc_playbooks WHERE id = $1", playbook_id)
    if r == "DELETE 0":
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    return {"deleted": playbook_id}


@app.get("/playbooks/executions")
async def list_executions(limit: int = 20):
    async with app.state.db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, executed_at, case_id, playbook_name, actions_taken
            FROM soc_playbook_executions
            ORDER BY executed_at DESC LIMIT $1
        """, limit)
    executions = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("actions_taken"), str):
            d["actions_taken"] = json.loads(d["actions_taken"])
        executions.append(d)
    return {"total": len(executions), "executions": executions}


@app.get("/")
async def root():
    return {
        "service": "SOC AI Agent",
        "version": "2.0.0",
        "features": ["pgvector memory", "skill learning", "EMA feedback", "MITRE context"],
        "endpoints": {
            "POST /analyze-case":      "Analyze a security alert",
            "POST /feedback/{id}":     "Analyst feedback → updates skill confidence",
            "GET  /skills":            "View all learned skills",
            "DELETE /skills/{id}":     "Remove a skill",
            "GET  /memory":            "View past case memories",
            "GET  /health":            "Health + stats",
            "GET  /docs":              "Swagger UI"
        }
    }
