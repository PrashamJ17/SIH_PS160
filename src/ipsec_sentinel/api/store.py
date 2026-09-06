"""Where analysed reports live between requests.

In memory and bounded. A bound matters more than it looks: without one, a server that
anyone can upload to grows until it is killed, and "the analyser died overnight" is a
denial of service that needs no attacker — just a busy week.

Deliberately not a database. Reports are derived data; the capture is the source of
truth and the operator has it. Persisting them would mean holding an estate's tunnel
inventory, endpoint addresses and traffic volumes on disk in a service that is reachable
over the network, which is a larger promise than this project should make quietly.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from ipsec_sentinel.report.models import Report

DEFAULT_CAPACITY: Final = 32


@dataclass(frozen=True)
class StoredReport:
    report_id: str
    report: Report
    source: str
    stored_at: datetime


class ReportStore:
    """A bounded, thread-safe map of report id to report.

    Thread-safe because a server runs handlers concurrently, and the eviction below is a
    read-modify-write. Losing a report to a race would be a confusing 404 for a caller
    that had just been handed the id.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("a store that holds nothing cannot serve a report it just made")
        self.capacity = capacity
        self._items: OrderedDict[str, StoredReport] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, report: Report, source: str) -> StoredReport:
        stored = StoredReport(
            report_id=uuid.uuid4().hex,
            report=report,
            source=source,
            stored_at=datetime.now(UTC),
        )
        with self._lock:
            self._items[stored.report_id] = stored
            while len(self._items) > self.capacity:
                self._items.popitem(last=False)
        return stored

    def get(self, report_id: str) -> StoredReport | None:
        with self._lock:
            stored = self._items.get(report_id)
            if stored is not None:
                self._items.move_to_end(stored.report_id)
            return stored

    def latest(self) -> StoredReport | None:
        with self._lock:
            return next(reversed(self._items.values()), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
