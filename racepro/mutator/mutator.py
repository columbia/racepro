from racepro.execgraph import ExecutionGraph

class Mutator:
    def process_events(self, events, options={}):
        raise NotImplementedError()

    def __or__(self, mutator):
        return Pipe(self, mutator)

    def __ror__(self, other):
        if isinstance(other, ExecutionGraph):
            from cat_graph import CatGraph
            return CatGraph(other) | self
        return Cat(other) | self

    def __iter__(self):
        return self.process_events(None, {})

class Pipe(Mutator):
    def __init__(self, lmutator, rmutator):
        self.lmutator = lmutator
        self.rmutator = rmutator

    def process_events(self, events, options):
        events = self.lmutator.process_events(events, options)
        events = self.rmutator.process_events(events, options)
        return events

class Cat(Mutator):
    def __init__(self, events):
        self.events = events

    def process_events(self, *args):
        return self.events
