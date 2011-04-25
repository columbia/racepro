from racepro import unistd
from vectorclock import *
from session import *
from itertools import *
from collections import *
import networkx
import scribe
import logging
import sys

class Node(Event):
    def __init__(self, graph, scribe_event):
        Event.__init__(self, scribe_event)
        self.graph = graph
        self.vclock = None

    def __repr__(self):
        if self.proc is None:
            return Event.__repr__(self)
        try:
            return "%d:%d" % (self.proc.pid, self.syscall_index)
        except:
            return str(self)

    def next_node(self):
        return (node for node in self.graph.successors_iter(self)
                if node.proc == self.proc).next()

class ExecutionGraph(networkx.DiGraph, Session):
    def __init__(self, events):
        networkx.DiGraph.__init__(self)
        Session.__init__(self, (Node(self, e) for e in events))

        self._build_graph()
        self._dependency_ps()
        self._dependency_fifo()
        self._dependency_signal()
        self._compute_vclocks()

    def edges_labeled(self, value):
        return ((u,v) for (u,v,d) in self.edges_iter(data=True)
                if d.get('label') == value)

    def nodes_typed(self, type):
        return (n for (n,d) in self.nodes_iter(data=True)
                if d.get('type') == type)

    def _build_graph(self):
        # We add all the nodes with their canonical edges for each proc
        for proc in self.processes.itervalues():
            proc.first_anchor      = Node(self, '%d:first_anchor' % proc.pid)
            proc.first_anchor.proc = proc
            self.add_node(proc.first_anchor)
            proc.last_anchor       = Node(self, '%d:last_anchor' % proc.pid)
            proc.last_anchor.proc  = proc
            self.add_node(proc.last_anchor)

            ancestor = proc.first_anchor
            for sys in proc.syscalls:
                type = None
                if sys.nr in unistd.SYS_fork and sys.ret > 0:
                    type = 'fork'
                elif sys.nr in unistd.SYS_wait and sys.ret > 0:
                    type = 'wait'
                elif sys.nr in unistd.SYS_exit:
                    type = 'exit'
                self.add_node(sys, type=type)
                self.add_edge(ancestor, sys)
                ancestor = sys
            self.add_edge(ancestor, proc.last_anchor)

    def _dependency_ps(self):
        for node in self.nodes_typed('fork'):
            child = self.processes[node.ret]
            self.add_edge(node, child.first_anchor, label='fork')

        for node in self.nodes_typed('wait'):
            child = self.processes[node.ret]
            self.add_edge(child.last_anchor, node, label='exit')

    def _dependency_fifo(self):
        for fifo in self.fifos:
            buf = 0
            write_left = 0  # data "left" in the first write
            writes = deque()

            write_iter = iter(fifo.writes)

            for read_sys in fifo.reads:
                if read_sys.ret < 0:
                    # TODO HB from a non-blocking read that returns -EAGAIN
                    # to the next write
                    continue
                read_bytes = read_sys.ret

                while buf < read_bytes:
                    try:
                        write_sys = write_iter.next()
                    except StopIteration:
                        raise ValueError("Not enough fifo writes :(")

                    if write_sys.ret < 0:
                        continue
                    written_bytes = write_sys.ret
                    buf += written_bytes
                    writes.append((write_sys, written_bytes))

                # add HB nodes from previous writes to us
                for write_sys, _ in writes:
                    if read_sys.proc != write_sys.proc:
                        self.add_edge(write_sys, read_sys, label='fifo')

                # discard previous writes which have been consumed
                while read_bytes > 0:
                    if write_left == 0:
                        write_left = writes[0][1]
                    nr = min([write_left, read_bytes])
                    buf -= nr
                    read_bytes -= nr
                    write_left -= nr
                    if write_left == 0:
                        writes.popleft()

    def _dependency_signal(self):
        for sig in self.signals:
            self.add_edge(sig.send.syscall, sig.recv.syscall, label='signal')

    def _compute_vclocks(self):
        for node in networkx.algorithms.dag.topological_sort(self):
            vc = reduce(lambda vc, node: vc.merge(node.vclock),
                        self.predecessors_iter(node), VectorClock())
            node.vclock = vc.tick(node.proc)

    def crosscut(self, cut_nodes):
        if len(cut_nodes) == 0:
            raise ValueError('Give me some nodes')
        for n1, n2 in combinations(cut_nodes, 2):
            if not n1.vclock.race(n2.vclock):
                raise ValueError('Cut nodes HB error: %s vs %s !' % (n1, n2))

        vc = reduce(lambda vc, node: vc.merge(node.vclock),
                    cut_nodes, VectorClock())
        cut_procs = map(lambda node: node.proc, cut_nodes)

        def get_clock_node(proc):
            clock = vc[proc]
            if not proc in cut_procs:
                # This is where we explicitly say that we want to include the
                # syscall that got us here
                clock += 1

            if clock == 0 or clock == 1:
                return proc.first_anchor
            if clock >= len(proc.syscalls) + 2:
                return proc.last_anchor
            return proc.syscalls[clock-2]

        return map(lambda proc: get_clock_node(proc), self.processes.values())
