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
    def __init__(self, scribe_event):
        Event.__init__(self, scribe_event)
        self.vclock = None

    @staticmethod
    def anchor(proc):
        e = Node(scribe.EventFence())
        e.proc = proc
        return e

    def __repr__(self):
        if self.proc is None:
            return Event.__repr__(self)
        try:
            syscall_index = self.syscall_index
        except:
            syscall_index = -1
        return "%d:%d" % (self.proc.pid, syscall_index)

class ExecutionGraph(networkx.DiGraph, Session):
    def __init__(self, events):
        """Build the execution DAG from the execution log.
        """
        networkx.DiGraph.__init__(self)
        Session.__init__(self, (Node(e) for e in events))

        self._dependency_fifo()

        init = self.init_proc
        init.anchor = Node.anchor(init)
        self.add_node(init.anchor)
        self._build_graph(init)

    def _build_graph(self, proc):
        """Build the execution DAG from the execution log, as follows:
        - New processes begin with a node 'pid'
        - Syscalls add a node 'pid:syscall' (and edge from previous)
        - Syscall fork() creates a new process and an edge to it 
        - Syscall exit() adds a node 'pid:exit' (and edge from previous)
        - Syscall wait() adds an edge from the child's exit() syscall
        - Node attribute 'index=str(I)' for event index in global list
        - Resource access add edge from the previous user to current
        (note: attributes must be strings)
        """
        ancestor = proc.anchor

        for sys in proc.syscalls:
            if sys.nr in unistd.SYS_fork and sys.ret > 0:
                newpid = sys.ret
                self.add_node(sys, type='fork')

                child = self.processes[newpid]
                child.anchor = Node.anchor(child)
                self.add_node(child.anchor)
                self.add_edge(sys, child.anchor, label='fork')

                self._build_graph(child)

            elif sys.nr in unistd.SYS_wait and sys.ret > 0:
                pid = sys.ret
                self.add_node(sys, type='wait')

                last = self.processes[pid].syscalls[-1]
                self.add_node(last)
                self.add_edge(last, sys, label='exit')

            elif sys.nr in unistd.SYS_exit:
                self.add_node(sys, type='exit')

            # unless node already exists (from dependcies HBs) - skip it
            # (otherwise, we need to connect it)
            elif sys not in self.nodes():
                continue

            self.add_edge(ancestor, sys)
            ancestor = sys

    def _dependency_fifo(self):
        """Add HB dependencies due to pipes and sockets"""
        for fifo in self.fifos:
            buf = 0
            write_left = 0  # data "left" in the first write
            writes = deque()

            if len(fifo.reads) == 0:
                continue

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

                dst = read_sys

                # add HB nodes from previous writes to us
                for write_sys, written_bytes in writes:
                    if read_sys.proc != write_sys.proc:
                        src = write_sys
                        self.add_edge(src, dst, label='fifo')

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
        """ADD HB dependencies due to signal send/receive (cookies)"""
        for sig in self.session.signals:
            self.add_edge(Node(sig.send), Node(sig.recv), label='signal')

    def compute_vclocks(self):
        """Compute the vector-clocks of nodes in the execution graph.
        """
        init = self.session.init_proc
        init.anchor.vclock = VectorClock().tick(init)

        for node in networkx.algorithms.dag.topological_sort(self):
            vc = node.vclock
            tick = False

            for next in self.neighbors(node):
                # need to create vclock for this node ?
                if not next.vclock:
                    next.vclock = vc.tick(next.proc)
                else:
                    next.vclock = next.vclock.merge(vc)

                # is this an edge that should cause a tick ?
                if node.proc != next.proc:
                    if self.edge[node][next]['type'] in ['fork', 'signal']:
                        tick = True
                else:
                    # remember for below
                    tnode = next

            if tick:
                # tick before the merge, but w/o effect on @vc
                tnode.vclock = tnode.vclock.merge(vc.tick(proc))

        # @ticks will map from a <proc, clock> tuple to the first
        # syscall (syscnt) by which proc that value of local clock.
        #
        # We deliberately include in the map syscnt=0 which doesn't really
        # map to a real system call, because it doesn't help special case
        # it here: we have to deal with clone() and clone() returns anyway
        ticks = dict()
        for node in self.nodes:
            c = node.vclock[node.proc]
            if (proc, c) in ticks:  # use earlier ones
                if node.event.syscall_index < ticks[(proc, c)].syscall_index:
                    ticks[(proc, c)] = node.event
            else:
                ticks[(proc, c)] = node.event

    class SysLoc:
        def __init__(self, syscall, after=None, before=None):
            self.syscall = syscall
            if after is not None:
                self.after = after
            if before is not None:
                self.after = not before

    def crosscut_graph(self, anchors):
        """Given a list of initial nodes in the graph, find a consistent
        crosscut, such that both nodes are just about to be executed.
        Returns bookmarks dict of the cut, or None if none found
        @anchors: list of (graph) nodes
        """



        # YJF: improved version
        # FIXME: (1) should just merge syscnt and vector clock.
        #        (2) should create special nodes to represent process
        #            start and exit.  these nodes are not connected to
        #            nodes in other processes

        # if any of the anchors HB another anchor - we're screwed
        for n1, n2 in combinations(anchors, 2):
            assert not n1.vclock.race(n2.vclock), \
                'Anchor nodes inconsistency: %s vs %s !' % (n1, n2)


        # given @anchors with clock @vcs, find a set nof nodes N in each
        # process, s.t. each pair of nodes in N are concurrent.
        #
        # algorithm: for process i
        #    find local clock ci s.t. ci = max(vc[i] for vc in vcs)
        #    find the first node n with vc such that vc[i] = ci+1
        #    take the edge from previous node -> n

        # proof that this cut does not violate causality:
        #    suppose ni --> nj, and ni is not taken, but nj is.
        #         
        #         ni not taken ==> ni[i] > ci
        #         ni --> nj ==> ni[j] <= nj[j]
        #
        #         nj[j] has a clock <= cj
        #             ==> ni --> last node with cj in process j
        #         last node with cj in process j is a fork 
        #             ==> this node --> all anchors  
        #             ==> ni --> all anchors so ni[i] must <= ci
                
        logging.debug('finding cut for nodes %s' % (", ".join(anchors)))

        vc = reduce(lambda vc, n: vc.merge(n.vclock), anchors, VectorClock())

        logging.debug('merged clocks %s' % vc)
        logging.debug('ticks array %s' %
                      ([(p.pid, c, s) for ((p, c), s) in self.ticks.items()]))

        cut = dict(lambda n: (n.proc, SysLoc(n.event, before=True)), anchors)

        for proc in self.session.processes.itervalues():
            if proc in map(lambda n: n.proc, anchors):
                continue

            # find the last time we heard from pid
            c = vc[proc]
            logging.debug("pid=%d, local clock=%d" % (pid, c))

            if (proc, c + 1) in ticks:
                # normal case: stop before the syscall
                cut[proc] = ticks[(proc, c + 1)]
            else:
                # special case: process already exited
                assert (c > 0), 'Invalid syscall count %d' % c
                cut[proc] = None


        logging.debug('temp-cut: %s' % cut)
        # convert cut to bookmarks understandable by save_events()
        # we use two passes (first cut, then marks) because when checking
        # if a child process has been cloned or not, we must make sure
        # that we have computed the cut
        marks = dict()
        for proc, sysloc in cut.iteritems():
            if sysloc.syscall not in map(lambda n: n.event, anchors):
                continue

            # Exception: for a process that was stopped on syscall 0
            # means that our vector-clock didn't know about the
            # process. This could be either if the process was not
            # forked yet, but also if the process was __just_ forked
            # but not communicate to us.  
            #
            # We need the extra hack for the second case because the way
            # we log clone() is awkward: if a clone() call is logged, both
            # returns from clone() in the parent and the child processes
            # must be in the log

            predec = self.predecessors(proc.anchor)
            assert predec, "only the first process %s? can't have race!" % proc
            assert len(predec)>0, 'More than one parent for %s !' % proc

            prev = predec[0]
            logging.debug('parent %s, child %s, clone@%d, cut@%s'
                          % (prev.proc, proc, prev.event.sycall_index, cut[prev]))

            if cut[proc].syscall.syscall_index <= prev.event.syscall_index: # clone() not in cut
                logging.debug('exclude child not yet cloned')
            else: # clone() in cut
                logging.debug("include child already cloned")
                marks[pid] = -1 # -1 to include clone ret in bookmarks

        logging.debug('found cut: %s' % marks)
        return marks
