from mutator import Mutator
from nodeloc_matcher import NodeLocMatcher

class TruncateQueue(Mutator):
    def __init__(self, where):
        self.matcher = NodeLocMatcher(where)

    def process_events(self, events):
        truncate_procs = set()

        def may_set_truncate(event, before):
            if self.matcher.match(event, before):
                truncate_procs.add(event.proc)

        for event in events:
            may_set_truncate(event, before=True)
            if event.proc not in truncate_procs:
                yield event
            may_set_truncate(event, before=False)
