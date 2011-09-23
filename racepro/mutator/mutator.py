from racepro.execgraph import ExecutionGraph

class Mutator:
    def process_events(self, events, options={}):
        raise NotImplementedError()

    def __or__(self, mutator):
        from pipe import Pipe
        return Pipe(self, mutator)

    def __ror__(self, other):
        if isinstance(other, ExecutionGraph):
            from cat_graph import CatGraph
            return CatGraph(other) | self
        from cat import Cat
        return Cat(other) | self

    def __iter__(self):
        self.start({})
        return self.process_events(None)

    def start(self, env):
        pass
