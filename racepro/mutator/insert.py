from mutator import Mutator
from nodeloc_matcher import NodeLocMatcher

class Insert(Mutator):
    def __init__(self, insersions):
        self.matcher = NodeLocMatcher(insersions)

    def process_events(self, events, options):
        for event in events:
            to_insert = self.matcher.match(event, before=True)
            if to_insert is not None:
                yield to_insert

            yield event

            to_insert = self.matcher.match(event, before=False)
            if to_insert is not None:
                yield to_insert
