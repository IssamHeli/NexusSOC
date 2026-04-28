import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _db_url() -> str:
    user = os.environ["DB_USER"]
    password = os.environ["DB_PASS"]
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    db = os.environ["DB_NAME"]
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"


def _do_migrations(connection):
    context.configure(connection=connection, target_metadata=None, include_schemas=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    engine = create_async_engine(_db_url())
    async with engine.connect() as conn:
        await conn.run_sync(_do_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


run_migrations_online()
