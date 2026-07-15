# -*- coding: utf-8 -*-
"""
jobs.py — rejestr zadań backupu w pamięci.

Poprzednio backup leciał w tle, logował print-em do stdout kontenera,
a frontend po sztywnych 16 sekundach ogłaszał "Backup zakończony"
niezależnie od wyniku. Teraz każdy backup ma job id, status i log,
które UI odpytuje aż do faktycznego zakończenia.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_JOBS_KEPT = 200


@dataclass
class Job:
    id: str
    title: str
    status: str = "w trakcie"        # running | done | failed
    log: List[str] = field(default_factory=list)
    created: float = field(default_factory=time.time)
    finished: Optional[float] = None
    ok_count: int = 0
    fail_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "log": self.log,
            "created": self.created,
            "finished": self.finished,
            "ok_count": self.ok_count,
            "fail_count": self.fail_count,
        }


class JobRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}

    def create(self, title: str) -> Job:
        job = Job(id=secrets.token_urlsafe(8), title=title)
        with self._lock:
            self._jobs[job.id] = job
            self._prune()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def log(self, job: Job, msg: str) -> None:
        with self._lock:
            job.log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def finish(self, job: Job, ok: bool) -> None:
        with self._lock:
            job.status = "zakończone" if ok else "błąd"
            job.finished = time.time()

    def recent(self, n: int = 20) -> List[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)
            return jobs[:n]

    def _prune(self) -> None:
        if len(self._jobs) <= MAX_JOBS_KEPT:
            return
        for j in sorted(self._jobs.values(), key=lambda j: j.created)[:len(self._jobs) - MAX_JOBS_KEPT]:
            self._jobs.pop(j.id, None)


JOBS = JobRegistry()
