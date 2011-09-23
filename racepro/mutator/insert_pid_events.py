from mutator import Mutator
from racepro import session
import scribe

class InsertPidEvents(Mutator):
    def process_events(self, events, options):
        current = None
        for e in events:
            if e.is_a(scribe.EventPid):
                continue
            proc = e.proc
            if proc != current:
                yield session.Event(scribe.EventPid(proc.pid))
                current = proc
            yield e