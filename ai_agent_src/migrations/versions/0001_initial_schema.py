"""Initial schema — all tables from V1+V2 Phase 1

Revision ID: 0001
Revises:
Create Date: 2026-04-27
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EMBED_DIM = 768


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.execute(f"""
    CREATE TABLE IF NOT EXISTS ai_analysis (
        id                 SERIAL PRIMARY KEY,
        timestamp          TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        case_id            VARCHAR(100) NOT NULL,
        raw_alert          JSONB,
        ai_decision        VARCHAR(50),
        confidence         FLOAT,
        analysis_summary   TEXT,
        recommended_action TEXT
    )
    """)
    op.execute(f"ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS embedding vector({EMBED_DIM})")

    op.execute("CREATE INDEX IF NOT EXISTS idx_case_id   ON ai_analysis(case_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON ai_analysis(timestamp)")
    op.execute("""
    CREATE INDEX IF NOT EXISTS idx_mem_embed ON ai_analysis
        USING hnsw (embedding vector_cosine_ops)
        WHERE embedding IS NOT NULL
    """)

    op.execute(f"""
    CREATE TABLE IF NOT EXISTS soc_skills (
        id               SERIAL PRIMARY KEY,
        created_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at       TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        skill_name       VARCHAR(200) NOT NULL,
        pattern          TEXT NOT NULL,
        decision         VARCHAR(50),
        embedding        vector({EMBED_DIM}),
        confidence_score FLOAT DEFAULT 0.70,
        usage_count      INT   DEFAULT 0,
        success_count    INT   DEFAULT 0,
        mitre_techniques TEXT[]
    )
    """)
    op.execute("""
    CREATE INDEX IF NOT EXISTS idx_skill_embed ON soc_skills
        USING hnsw (embedding vector_cosine_ops)
        WHERE embedding IS NOT NULL
    """)

    op.execute("""
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
    )
    """)

    op.execute("""
    CREATE TABLE IF NOT EXISTS soc_playbook_executions (
        id            SERIAL PRIMARY KEY,
        executed_at   TIMESTAMPTZ DEFAULT NOW(),
        case_id       VARCHAR(100) NOT NULL,
        playbook_id   INT REFERENCES soc_playbooks(id) ON DELETE SET NULL,
        playbook_name VARCHAR(200),
        actions_taken JSONB
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_pb_exec_case ON soc_playbook_executions(case_id)")

    op.execute("""
    CREATE TABLE IF NOT EXISTS soc_incidents (
        id                SERIAL PRIMARY KEY,
        created_at        TIMESTAMPTZ DEFAULT NOW(),
        updated_at        TIMESTAMPTZ DEFAULT NOW(),
        incident_id       VARCHAR(100) UNIQUE NOT NULL,
        title             TEXT,
        status            VARCHAR(50)  NOT NULL DEFAULT 'open',
        severity          VARCHAR(50)  NOT NULL DEFAULT 'medium',
        case_ids          TEXT[]       NOT NULL DEFAULT '{}',
        kill_chain_phases TEXT[]       NOT NULL DEFAULT '{}',
        source_ips        TEXT[]       NOT NULL DEFAULT '{}',
        hostnames         TEXT[]       NOT NULL DEFAULT '{}',
        users             TEXT[]       NOT NULL DEFAULT '{}',
        attack_types      TEXT[]       NOT NULL DEFAULT '{}',
        mitre_techniques  TEXT[]       NOT NULL DEFAULT '{}',
        case_count        INT          NOT NULL DEFAULT 1
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_inc_status  ON soc_incidents(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_inc_updated ON soc_incidents(updated_at)")

    op.execute("""
    CREATE TABLE IF NOT EXISTS soc_users (
        id            SERIAL PRIMARY KEY,
        created_at    TIMESTAMPTZ DEFAULT NOW(),
        updated_at    TIMESTAMPTZ DEFAULT NOW(),
        username      VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT        NOT NULL,
        role          VARCHAR(20) NOT NULL DEFAULT 'analyst',
        is_active     BOOLEAN     NOT NULL DEFAULT TRUE
    )
    """)

    op.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id          BIGSERIAL PRIMARY KEY,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        user_id     INT REFERENCES soc_users(id) ON DELETE SET NULL,
        username    VARCHAR(100),
        method      VARCHAR(10),
        endpoint    TEXT,
        status_code INT,
        duration_ms INT,
        client_ip   TEXT,
        user_agent  TEXT
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_logs")
    op.execute("DROP TABLE IF EXISTS soc_users")
    op.execute("DROP TABLE IF EXISTS soc_incidents")
    op.execute("DROP TABLE IF EXISTS soc_playbook_executions")
    op.execute("DROP TABLE IF EXISTS soc_playbooks")
    op.execute("DROP TABLE IF EXISTS soc_skills")
    op.execute("DROP TABLE IF EXISTS ai_analysis")
