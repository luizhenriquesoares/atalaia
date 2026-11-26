"""Scan lifecycle: authorization gate, background execution, persistence of findings."""
from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import func, select, true, update
from sqlalchemy.orm import Session

from . import audit
from .config import Settings
from .models import Finding, Scan, ScanFindingLink, Target, utcnow
from .netguard import TargetNotAllowed, assert_allowed_host, pick_ip
from .scanner.engine import PROFILES, ScanConfig, ScanResult, run_scan
from .security import SecretBox

log = logging.getLogger("atalaia.scans")

ACTIVE = ("queued", "running")
INPUT_CHECKS = {"xss-reflected", "xss-dom", "xss-stored", "sqli-error", "sqli-boolean", "ssti",
                "path-traversal", "open-redirect", "crlf-injection"}
BROWSER_CHECKS = {"xss-dom"}        # only a scan that used the headless browser can re-test these
HOST_PROBE_CHECKS = {
    "exposed-git", "exposed-env", "exposed-backup", "exposed-private-key", "exposed-debug", "exposed-api-docs",
    "graphql-introspection", "security-txt-missing", "cors-reflect-credentials", "cors-reflect",
    "cors-null-origin", "trace-enabled", "no-https", "no-https-redirect", "tls-cert-expired",
    "tls-cert-expiring", "tls-cert-invalid", "tls-legacy-protocol", "host-header-injection",
    "windows-api-arbitrary-file-read",
}


class ScanRefused(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def verification_valid(target: Target, settings: Settings) -> bool:
    if not target.verified_at:
        return False
    return utcnow() - target.verified_at <= timedelta(days=settings.verification_ttl_days)


def create_scan(db: Session, settings: Settings, target: Target, profile: str, actor: str, ip: str = "") -> Scan:
    """The single entry point that creates scans. Enforces the authorization rules."""
    if profile not in PROFILES:
        raise ScanRefused("Perfil de varredura inválido", 422)
    try:
        assert_allowed_host(target.host, allow_private=settings.allow_private_targets)
    except TargetNotAllowed as exc:
        raise ScanRefused(str(exc), 403) from exc
    busy = db.scalar(select(func.count()).select_from(Scan).where(
        Scan.target_id == target.id, Scan.status.in_(ACTIVE)))
    if busy:
        raise ScanRefused("Já existe uma varredura em andamento para este alvo")
    running = db.scalar(select(func.count()).select_from(Scan).where(
        Scan.org_id == target.org_id, Scan.status.in_(ACTIVE)))
    if running >= settings.max_concurrent_scans_per_org:
        raise ScanRefused(f"Limite de {settings.max_concurrent_scans_per_org} varreduras simultâneas atingido", 429)
    scan = Scan(org_id=target.org_id, target_id=target.id, profile=profile, status="queued", triggered_by=actor)
    db.add(scan)
    db.flush()
    audit.record(db, org_id=target.org_id, actor=actor, action="scan.start", resource_type="scan",
                 resource_id=scan.id, ip=ip, details={"target": target.base_url, "profile": profile})
    return scan


def covered(profile: str, check_id: str, method: str, browser_used: bool = True) -> bool:
    """Whether a scan with *profile* would have re-detected a finding of this kind."""
    if check_id in BROWSER_CHECKS and not browser_used:
        return False
    if check_id in INPUT_CHECKS:
        return profile == "full" or (profile == "standard" and method == "GET")
    if check_id in HOST_PROBE_CHECKS:
        return profile in ("standard", "full")
    return True


def persist_result(db: Session, scan: Scan, result: ScanResult) -> dict:
    now = utcnow()
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "new": 0, "fixed": 0, "reopened": 0}
    seen_ids: set[str] = set()
    existing = {f.fingerprint: f for f in db.execute(
        select(Finding).where(Finding.target_id == scan.target_id)).scalars()}
    for sf in result.findings:
        finding = existing.get(sf.fingerprint)
        is_new = False
        if finding is None:
            finding = Finding(org_id=scan.org_id, target_id=scan.target_id, fingerprint=sf.fingerprint,
                              first_scan_id=scan.id, first_seen=now, status="open")
            db.add(finding)
            existing[sf.fingerprint] = finding
            is_new = True
            summary["new"] += 1
        elif finding.status == "fixed":
            finding.status = "open"
            finding.resolved_at = None
            finding.status_note = "Reaberto: detectado novamente após ter sido corrigido."
            is_new = True
            summary["reopened"] += 1
        for attr in ("check_id", "title", "severity", "confidence", "cwe", "owasp", "cvss", "url", "method",
                     "parameter", "evidence", "description", "remediation", "references"):
            setattr(finding, attr, getattr(sf, attr))
        finding.last_seen = now
        finding.last_scan_id = scan.id
        db.flush()
        seen_ids.add(finding.id)
        db.add(ScanFindingLink(scan_id=scan.id, finding_id=finding.id, is_new=is_new))
        if finding.status == "open":
            summary[sf.severity] += 1

    # A finding is closed only when this scan really re-tested it: the scan finished, its profile
    # includes the check, and the finding's URL was requested again. A page the crawler did not
    # reach this time proves nothing, so its findings stay open.
    complete = not result.canceled and not result.budget_exhausted and result.pages_crawled > 0
    if complete:
        for finding in existing.values():
            if finding.id and finding.id not in seen_ids and finding.status == "open" \
                    and covered(scan.profile, finding.check_id, finding.method, result.browser_used) \
                    and (urlsplit(finding.url).path or "/") in result.paths_requested:
                finding.status = "fixed"
                finding.resolved_at = now
                finding.status_note = "Não detectado na varredura mais recente."
                summary["fixed"] += 1
    return summary


class ScanManager:
    """Executes scans taken from a queue that lives in the database.

    Any number of processes may run a ScanManager against the same database: the API process
    (embedded mode) and/or dedicated `python -m atalaia.worker` processes. A scan is claimed with
    an atomic UPDATE, so it runs exactly once; cancellation is a flag in the database, so it works
    no matter which process owns the scan; and a scan whose worker died is detected by its stale
    heartbeat and marked as failed.
    """

    def __init__(self, settings: Settings, session_factory, box: SecretBox):
        self.settings = settings
        self.session_factory = session_factory
        self.box = box
        self.worker_id = f"w-{uuid.uuid4().hex[:12]}"
        self.executor = ThreadPoolExecutor(max_workers=settings.scan_workers, thread_name_prefix="scan")
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._loop: threading.Thread | None = None
        self._last_schedule = 0.0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._loop is None:
            self._loop = threading.Thread(target=self._run_loop, daemon=True, name="scan-queue")
            self._loop.start()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1):
                pass
        except KeyboardInterrupt:
            pass
        self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            for ev in self._cancel.values():
                ev.set()
        if self._loop:
            self._loop.join(timeout=10)
        self.executor.shutdown(wait=True, cancel_futures=True)

    def wake(self) -> None:
        """Called after a scan is queued or a cancellation is requested, to act without delay."""
        self._wake.set()

    def submit(self, scan_id: str | None = None) -> None:
        self.wake()

    def cancel(self, scan_id: str) -> None:
        """Request cancellation; whichever worker owns the scan will stop it."""
        with self.session_factory() as db:
            queued = db.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "queued")
                                .values(status="canceled", finished_at=utcnow(), stage="done"))
            if queued.rowcount == 0:
                db.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running")
                           .values(cancel_requested=True))
            db.commit()
        self.wake()

    def wait_idle(self, timeout: float = 60) -> bool:
        """Test helper: wait until no scan is queued or running anywhere."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.session_factory() as db:
                active = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(ACTIVE)))
            with self._lock:
                mine = len(self._cancel)
            if not active and not mine:
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------ queue loop
    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("queue tick failed")
            self._wake.wait(self.settings.worker_poll_seconds)
            self._wake.clear()

    def tick(self) -> None:
        """One pass of the queue loop: heartbeat, cancellations, dead workers, schedule, claims."""
        with self._lock:
            mine = list(self._cancel)
        now = utcnow()
        with self.session_factory() as db:
            if mine:
                db.execute(update(Scan).where(Scan.id.in_(mine), Scan.worker_id == self.worker_id)
                           .values(heartbeat_at=now))
                too_long = now - timedelta(seconds=self.settings.max_scan_seconds)
                for scan_id, requested in db.execute(select(Scan.id, Scan.cancel_requested).where(
                        Scan.id.in_(mine), Scan.cancel_requested.is_(True) | (Scan.started_at < too_long))).all():
                    if not requested:
                        db.execute(update(Scan).where(Scan.id == scan_id).values(
                            error="Tempo máximo de varredura excedido; resultado parcial."))
                    with self._lock:
                        ev = self._cancel.get(scan_id)
                    if ev:
                        ev.set()
            cutoff = now - timedelta(seconds=self.settings.worker_stale_seconds)
            dead = db.execute(select(Scan).where(
                Scan.status == "running", Scan.id.not_in(mine) if mine else true(),
                (Scan.heartbeat_at.is_(None)) | (Scan.heartbeat_at < cutoff))).scalars().all()
            for scan in dead:
                scan.status = "failed"
                scan.error = "Varredura interrompida: o processo que a executava parou de responder."
                scan.finished_at = now
                audit.record(db, org_id=scan.org_id, actor="system", action="scan.failed", resource_type="scan",
                             resource_id=scan.id, details={"reason": "stale heartbeat", "worker": scan.worker_id})
            db.commit()
        if self.settings.enable_scheduler and time.monotonic() - self._last_schedule >= 30:
            self._last_schedule = time.monotonic()
            self.run_due()
        self._claim()

    recover = tick      # kept for callers of the old API: a tick reaps scans left by dead workers

    def _claim(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                free = self.settings.scan_workers - len(self._cancel)
            if free <= 0:
                return
            claimed = None
            with self.session_factory() as db:
                for scan_id in db.execute(select(Scan.id).where(Scan.status == "queued")
                                          .order_by(Scan.created_at).limit(5)).scalars().all():
                    won = db.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "queued").values(
                        status="running", worker_id=self.worker_id, heartbeat_at=utcnow(),
                        started_at=utcnow(), stage="starting"))
                    db.commit()
                    if won.rowcount == 1:
                        claimed = scan_id
                        break
            if claimed is None:
                return
            with self._lock:
                self._cancel[claimed] = threading.Event()
            self.executor.submit(self._run, claimed)

    # ------------------------------------------------------------------ execution
    def _run(self, scan_id: str) -> None:
        with self._lock:
            cancel_event = self._cancel.get(scan_id) or threading.Event()
        try:
            self._execute(scan_id, cancel_event)
        except Exception as exc:  # never let a worker die silently
            log.exception("scan %s failed", scan_id)
            with self.session_factory() as db:
                scan = db.get(Scan, scan_id)
                if scan and scan.status in ACTIVE:
                    scan.status = "failed"
                    scan.error = f"Erro interno: {type(exc).__name__}"
                    scan.finished_at = utcnow()
                    db.commit()
        finally:
            with self._lock:
                self._cancel.pop(scan_id, None)
            self.wake()         # a slot is free: claim the next queued scan right away

    def _execute(self, scan_id: str, cancel_event: threading.Event) -> None:
        with self.session_factory() as db:
            scan = db.get(Scan, scan_id)
            if not scan or scan.status != "running" or scan.worker_id != self.worker_id:
                return
            target = db.get(Target, scan.target_id)
            # Authorization is re-checked at execution time, not only when the scan was queued.
            problem = None
            pinned_ip = None
            if not verification_valid(target, self.settings):
                problem = "Alvo sem verificação de propriedade válida."
            else:
                try:
                    pinned_ip = pick_ip(assert_allowed_host(
                        target.host, allow_private=self.settings.allow_private_targets))
                except TargetNotAllowed as exc:
                    problem = str(exc)
            if problem:
                scan.status, scan.error, scan.finished_at = "failed", problem, utcnow()
                db.commit()
                return
            headers = self.box.decrypt_json(target.auth_headers_enc) if target.auth_headers_enc else {}
            config = ScanConfig(
                base_url=target.base_url, profile=scan.profile, max_pages=self.settings.max_pages,
                rps=min(target.max_rps or self.settings.default_rps, self.settings.max_rps),
                max_requests=self.settings.max_requests, headers=headers or {},
                excludes=list(target.excludes or []), pinned_ip=pinned_ip,
                browser=self.settings.browser != "off", browser_max_pages=self.settings.browser_max_pages,
                browser_third_party=self.settings.browser_third_party,
                browser_allow_private_third_party=self.settings.allow_private_targets,
                browser_sandbox=self.settings.browser_sandbox)

        last = [0.0]

        def progress(stage: str, pct: int, requests: int, pages: int) -> None:
            if time.monotonic() - last[0] < 0.5:
                return
            last[0] = time.monotonic()
            try:
                with self.session_factory() as pdb:
                    pdb.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running").values(
                        stage=stage, progress=pct, requests_sent=requests, pages_crawled=pages,
                        heartbeat_at=utcnow()))
                    pdb.commit()
            except Exception:
                log.debug("progress update failed", exc_info=True)

        result = asyncio.run(run_scan(config, cancel_event=cancel_event, progress=progress))

        with self.session_factory() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status != "running" or scan.worker_id != self.worker_id:
                return      # target deleted, or the scan was reaped and no longer belongs to this worker
            scan.summary = persist_result(db, scan, result)
            scan.summary["rendered"] = result.pages_rendered
            scan.pages_crawled = result.pages_crawled
            scan.requests_sent = result.requests_sent
            scan.notes = result.notes
            scan.finished_at = utcnow()
            scan.stage = "done"
            if result.canceled:
                scan.status = "canceled"
            elif result.pages_crawled == 0:
                scan.status = "failed"
                scan.error = "O alvo não respondeu a nenhuma requisição."
            else:
                scan.status = "completed"
                scan.progress = 100
            audit.record(db, org_id=scan.org_id, actor="system", action=f"scan.{scan.status}",
                         resource_type="scan", resource_id=scan.id,
                         details={"requests": result.requests_sent, "pages": result.pages_crawled,
                                  "summary": scan.summary, "worker": self.worker_id})
            db.commit()

    # ------------------------------------------------------------------ scheduler
    def run_due(self) -> list[str]:
        """Queue scans for targets whose schedule is due. Safe to call from several processes:
        the schedule slot is taken with an atomic UPDATE."""
        started = []
        with self.session_factory() as db:
            due = db.execute(select(Target.id, Target.next_scan_at, Target.schedule).where(
                Target.schedule != "none", Target.next_scan_at.is_not(None),
                Target.next_scan_at <= utcnow())).all()
            for target_id, due_at, schedule in due:
                won = db.execute(update(Target).where(Target.id == target_id, Target.next_scan_at == due_at)
                                 .values(next_scan_at=next_run(schedule)))
                db.commit()
                if won.rowcount != 1:
                    continue
                target = db.get(Target, target_id)
                try:
                    scan = create_scan(db, self.settings, target, target.schedule_profile, "scheduler")
                    db.commit()
                    started.append(scan.id)
                except ScanRefused as exc:
                    db.rollback()
                    audit.record(db, org_id=target.org_id, actor="scheduler", action="scan.refused",
                                 resource_type="target", resource_id=target_id, details={"reason": str(exc)})
                    db.commit()
        if started:
            self.wake()
        return started


def next_run(schedule: str):
    if schedule == "daily":
        return utcnow() + timedelta(days=1)
    if schedule == "weekly":
        return utcnow() + timedelta(days=7)
    return None
