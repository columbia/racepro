from mutator import Mutator
from nodeloc_matcher import NodeLocMatcher

class TruncateQueue(Mutator):
    def __init__(self, where):
        self.matcher = NodeLocMatcher(where)
        self.num_procs = -1
        self.last_anchors = None

    def start(self, env):
        graph = env.get('graph')
        if graph is not None:
            self.num_procs = len(graph.processes)
            self.last_anchors = set(map(lambda (p): p.last_anchor,
                                        graph.processes.values()))

    def process_events(self, events):
        truncate_procs = set()
        stop_processing = [False]

        def truncate_queue(proc):
            truncate_procs.add(proc)
            if len(truncate_procs) == self.num_procs:
                stop_processing[0] = True

        for event in events:
            if self.matcher.match(event, before=True):
                truncate_queue(event.proc)

            if event.proc not in truncate_procs:
                yield event

            if self.matcher.match(event, before=False):
                truncate_queue(event.proc)

            if self.last_anchors is not None and event in self.last_anchors:
                truncate_queue(event.proc)

            if stop_processing[0]:
                break
