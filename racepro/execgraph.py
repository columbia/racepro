import vectorclock
import session
import itertools
import collections
import networkx
import struct

import scribe
from racepro import unistd

class Node(session.Event):
    def __init__(self, graph, scribe_event):
        session.Event.__init__(self, scribe_event)
        self.graph = graph
        self.vclock = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        if self.proc is None:
            return session.Event.__repr__(self)
        try:
            return "%d:%d %s" % (self.proc.pid, self.syscall_index+1, str(self._scribe_event))
        except:
            return str(self._scribe_event)

    def prev_node(self):
        return (node for node in self.graph.predecessors_iter(self)
                if node.proc == self.proc).next()

    def next_node(self):
        return (node for node in self.graph.successors_iter(self)
                if node.proc == self.proc).next()

class NodeLoc:
    def __init__(self, node, loc):
        self.node = node
        if loc == 'before':
            self.before = True
            self.after = False
        elif loc == 'after':
            self.before = False
            self.after = True
        else:
            raise ValueError

    @property
    def vclock(self):
        if self.before:
            try:
                return self.node.prev_node().vclock
            except StopIteration:
                pass
        return self.node.vclock

    def __eq__(self, nl):
        return self.node == nl.node and self.before == nl.before

    def __hash__(self):
        return hash(self.node) ^ hash(self.before)

    def __repr__(self):
        return repr(self.node) + ('a' if self.after else 'b')

class ExecutionGraph(networkx.DiGraph, session.Session):
    def __init__(self, events):
        networkx.DiGraph.__init__(self)
        session.Session.__init__(self, (Node(self, e) for e in events))

        self._build_graph()
        self._dependency_ps()
        self._dependency_fifo()
        self._dependency_signal()
        self._compute_vclocks()

    def edges_labeled(self, value, nbunch=None):
        return ((u,v) for (u,v,d) in self.edges_iter(nbunch, data=True)
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
                elif sys.nr in [unistd.NR_waitpid, unistd.NR_wait4] and sys.ret > 0:
                    type = 'wait'
                elif sys.nr == unistd.NR_waitid and sys.ret == 0:
                    if self._get_reaped_pid(sys) > 0:
                        type = 'wait'
                elif sys.nr in unistd.SYS_exit:
                    type = 'exit'
                if type:
                    self.add_node(sys, type=type)
                self.add_edge(ancestor, sys)
                ancestor = sys
            self.add_edge(ancestor, proc.last_anchor)

    def _get_reaped_pid(self, sys):
        if sys.nr in [unistd.NR_waitpid, unistd.NR_wait4] and sys.ret > 0:
            return sys.ret

        if sys.nr == unistd.NR_waitid:
            for e in sys.children:
                if e.is_a(scribe.EventDataExtra) and \
                        e.data_type == scribe.SCRIBE_DATA_INTERNAL:
                    (pid,) = struct.unpack('i', e.data)
                    if pid & scribe.SCRIBE_REAPED:
                        return pid & ~scribe.SCRIBE_REAPED
                    break
        return 0

    def _dependency_ps(self):
        for node in self.nodes_typed('fork'):
            child = self.processes[node.ret]
            self.add_edge(node, child.first_anchor, label='fork')

        for node in self.nodes_typed('wait'):
            pid = self._get_reaped_pid(node)
            child = self.processes[pid]
            self.add_edge(child.last_anchor, node, label='exit')

    def _dependency_fifo(self):
        for fifo in self.fifos:
            buf = 0
            write_left = 0  # data "left" in the first write
            writes = collections.deque()

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
            recv_syscall = (e for e in sig.recv.proc.events.after(sig.recv) if
                            e.is_a(scribe.EventSyscallExtra)).next()
            self.add_edge(sig.send.syscall, recv_syscall, label='signal')

    def _compute_vclocks(self):
        for node in networkx.algorithms.dag.topological_sort(self):
            vc = reduce(lambda vc, node: vc.merge(node.vclock),
                        self.predecessors_iter(node), vectorclock.VectorClock())
            node.vclock = vc.tick(node.proc)

    def crosscut(self, cut):
        if len(cut) == 0:
            raise ValueError('Give me some nodes')
        cut = map(lambda n: n if isinstance(n, NodeLoc) else NodeLoc(n, 'before'), cut)
        vc = reduce(lambda vc, nl: vc.merge(nl.vclock), cut, vectorclock.VectorClock())

        def get_clock_node(proc):
            clock = vc[proc]
            if clock == 0:
                fork = self.predecessors_iter(proc.first_anchor).next()
                if fork.vclock.before(vc):
                    return NodeLoc(proc.first_anchor, 'after')
                return NodeLoc(proc.first_anchor, 'before')
            elif clock == 1:
                return NodeLoc(proc.first_anchor, 'after')
            elif clock == len(proc.syscalls) + 2:
                return NodeLoc(proc.last_anchor, 'after')
            else:
                return NodeLoc(proc.syscalls[clock-2], 'after')

        proc_todo = set(self.processes.values()) - \
                    set(map(lambda nl: nl.node.proc, cut))
        return cut + map(lambda proc: get_clock_node(proc), proc_todo)
