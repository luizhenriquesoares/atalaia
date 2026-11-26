from __future__ import annotations

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.schema import CreateColumn
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    kwargs: dict = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=10000")
            if ":memory:" not in url:
                cur.execute("PRAGMA journal_mode=WAL")
            cur.close()
    return engine


def make_session_factory(engine):
    return sessionmaker(engine, expire_on_commit=False)


def ensure_schema(engine) -> None:
    """Create missing tables and add columns introduced by newer versions (additive only), so an
    existing database keeps working after an upgrade. Anything beyond adding columns needs a real
    migration tool."""
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # API and workers may start at the same time: only one of them changes the schema.
            conn.execute(text("SELECT pg_advisory_xact_lock(4174211091)"))
        Base.metadata.create_all(conn)
        inspector = inspect(conn)
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl = str(CreateColumn(column).compile(dialect=engine.dialect)).replace(" NOT NULL", "")
                default = getattr(column.default, "arg", None)
                if isinstance(default, bool):
                    ddl += f" DEFAULT {'TRUE' if default else 'FALSE'}" if engine.dialect.name != "sqlite" \
                        else f" DEFAULT {int(default)}"
                elif isinstance(default, (int, float)):
                    ddl += f" DEFAULT {default}"
                conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {ddl}"))
