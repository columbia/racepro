from mutator import Mutator
from racepro.execgraph import NodeLoc

class NodeLocDemux(Mutator):
    def process_events(self, events, options):
        for event in events:
            yield NodeLoc(event, 'before')
            yield NodeLoc(event, 'after')

class NodeLocMux(Mutator):
    def process_events(self, events, options):
        for event in events:
            if isinstance(event, NodeLoc) and event.after:
                continue
            yield event.node
