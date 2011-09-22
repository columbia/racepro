from mutator import Mutator
import itertools
import networkx

class CatGraph(Mutator):
    def __init__(self, graph):
        self.graph = graph

    def process_events(self, *args):
        def node_and_after(node):
            proc = node.proc
            if node == proc.first_anchor:
                return itertools.chain([node], proc.events)
            elif node == proc.last_anchor:
                return [node]
            return itertools.chain([node], proc.events.after(node))

        def events_of_node(node):
            try:
                next_node = node.next_node()
            except StopIteration:
                return node_and_after(node)
            return itertools.takewhile(lambda e: e != next_node,
                                       node_and_after(node))

        yield self.graph.events[0]
        for node in networkx.algorithms.dag.topological_sort(self.graph):
            for event in events_of_node(node):
                yield event
