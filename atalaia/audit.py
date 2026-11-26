"""Tamper-evident audit trail."""
from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, utcnow


def _digest(prev: str, entry: AuditLog) -> str:
    body = json.dumps([prev, entry.org_id, entry.actor, entry.action, entry.resource_type, entry.resource_id,
                       entry.ip, entry.details, entry.created_at.isoformat()], sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def record(db: Session, *, org_id: str, actor: str, action: str, resource_type: str = "",
           resource_id: str = "", ip: str = "", details: dict | None = None) -> AuditLog:
    """Append an entry. The caller commits; the entry joins the caller's transaction."""
    last = db.execute(select(AuditLog).where(AuditLog.org_id == org_id)
                      .order_by(AuditLog.id.desc()).limit(1).with_for_update()).scalar_one_or_none()
    entry = AuditLog(org_id=org_id, actor=actor, action=action, resource_type=resource_type,
                     resource_id=resource_id, ip=ip, details=details or {},
                     created_at=utcnow().replace(microsecond=0))
    entry.prev_hash = last.hash if last else ""
    entry.hash = _digest(entry.prev_hash, entry)
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session, org_id: str) -> dict:
    prev = ""
    count = 0
    for entry in db.execute(select(AuditLog).where(AuditLog.org_id == org_id).order_by(AuditLog.id)).scalars():
        count += 1
        if entry.prev_hash != prev or entry.hash != _digest(prev, entry):
            return {"valid": False, "entries": count, "broken_at": entry.id}
        prev = entry.hash
    return {"valid": True, "entries": count, "broken_at": None}
