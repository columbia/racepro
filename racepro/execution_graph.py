from racepro import unistd
from racepro.vectorclock import VectorClock
from itertools import *
from collections import *
import networkx
import scribe
import logging
import sys

class ExecutionGraph(networkx.DiGraph):
    def __init__(self, session, full=False, dependency=True, resources=False):
        """Build the execution DAG from the execution log.
        @full: if True, include all syscalls, else only fork/wait/exit
        @depends: if True, add additional HB dependencies (e.g. pipes)
        @resources: if True, add dependencies induced by resources
        Return a graph.
        """
        self.session = session

        networkx.DiGraph.__init__(self)
        self.add_node('1:0')

        if dependency:
            # add dependencies of mandatory HB
            self._dependency_pipe()
            self._dependency_signal()
            ## self._dependency_reparent()

        # build initial graph
        self._build_graph(self.session.process_list[0], full)

        if resources:
            # add dependencies of resources
            self._resources_graph()

    def make_node(self, pid, syscall):
        return str(pid) + ':' + str(syscall)

    def split_node(self, node):
        (pid, index) = node.split(':')
        proc = self.session.process_map[int(pid)]
        return (proc, int(index))

    def _build_graph(self, proc, full):
        """Build the execution DAG from the execution log, as follows:
        - The first node is '0'
        - New processes begin with a node 'pid'
        - Syscalls add a node 'pid:syscall' (and edge from previous)
        - Syscall fork() creates a new process and an edge to it 
        - Syscall exit() adds a node 'pid:exit' (and edge from previous)
        - Syscall wait() adds an edge from the child's exit() syscall
        - Node attribute 'index=str(I)' for event index in global list
        - Resource access add edge from the previous user to current
        (note: attributes must be strings)
        """
        pid = proc.pid
        ancestor = self.make_node(pid, 0)
        for p_ev in proc.events:
            event = p_ev.event
            if not isinstance(event, scribe.EventSyscallExtra):
                pass
            elif event.nr in unistd.Syscalls.SYS_fork and event.ret > 0:
                newpid = event.ret
                parent = self.make_node(pid, p_ev.syscnt)
                self.add_node(parent, index=str(p_ev.index), fork='1')
                self.add_edge(ancestor, parent)
                child = self.make_node(newpid, 0)
                self.add_node(child)
                self.add_edge(parent, child, fork='1', label='fork')
                self._build_graph(self.session.process_map[newpid], full)
                ancestor = parent
            elif event.nr in unistd.Syscalls.SYS_wait and event.ret > 0:
                newpid = event.ret
                node = self.make_node(pid, p_ev.syscnt)
                self.add_node(node, index=str(p_ev.index))
                self.add_edge(ancestor, node)
                child = self.make_node(newpid, self.session.process_map[newpid].syscnt)
                self.add_edge(child, node, label='exit')
                ancestor = node
            elif event.nr in unistd.Syscalls.SYS_exit:
                node = self.make_node(pid, p_ev.syscnt)
                self.add_node(node, index=str(p_ev.index), exit='1')
                self.add_edge(ancestor, node)
                ancestor = node
            elif full:
                node = self.make_node(pid, p_ev.syscnt)
                self.add_node(node, index=str(p_ev.index))
                self.add_edge(ancestor, node)
                ancestor = node
            else:
                # node already exists (from dependcies HBs) - connect it
                node = self.make_node(pid, p_ev.syscnt)
                if node in self.node:
                    self.add_edge(ancestor, node)
                    ancestor = node

    def _resources_graph(self):
        """Add OB dependencies due to resources to an execution graph"""

        for r in self.session.resource_list:
            prev, pind = self.session.r_ev_to_proc(r.events[0])
            pr_ev = list()
            nr_ev = list()
            serial = 0

            def add_resource_edges():
                tr_ev = product(pr_ev, nr_ev)

                for (prev, pind), (next, nind) in tr_ev:
                    if prev == next:
                        continue
                    logging.debug('%d:%d -> %d:%d' %
                                  (prev.pid,pind,next.pid,nind))
                    src = self.make_node(prev.pid, prev.events[pind].syscnt)
                    dst = self.make_node(next.pid, next.events[nind].syscnt)
                    if dst not in self[src]:
                        self.add_edge(src, dst,
                                      resource=str(r.id),
                                      label='r%d(%d)' % (r.id, serial))

            for r_ev in r.events:
                next, nind = self.session.r_ev_to_proc(r_ev)
                if r_ev.event.serial == serial:
                    nr_ev.append((next, nind))
                else:
                    add_resource_edges()
                    pr_ev = nr_ev
                    nr_ev = list([(next, nind)])
                    serial = r_ev.event.serial
            else:
                add_resource_edges()

    def _dependency_pipe(self):
        """Add HB dependencies due to pipes and sockets"""
        for pipe in self.session.pipe_e.values():
            pipe_buf = 0
            ri = 0  # current read event
            wi = 0  # current write event
            wleft = 0  # data "left" in the first write
            writes = deque()

            if len(pipe[0]) > 0:
                desc = pipe[0][0][0].event.desc
                if desc and desc not in self.session.pipe_d:
                    continue

            while ri < len(pipe[0]):
                read_rev, read_nr = pipe[0][ri]

                while pipe_buf < read_nr and wi < len(pipe[1]):
                    write_rev, write_nr = pipe[1][wi]
                    pipe_buf += write_nr
                    writes.append((write_rev, write_nr))
                    wi += 1

                p2, i2 = self.session.r_ev_to_proc(read_rev, sysind=True)
                sc2 = p2.events[i2].syscnt
                node2 = self.make_node(p2.pid, sc2)

                # add HB nodes from previous writes to us
                for write_rev, write_nr in writes:
                    p1, i1 = self.session.r_ev_to_proc(write_rev, sysind=True)
                    sc1 = p1.events[i1].syscnt
                    if p1 != p2:
                        node1 = self.make_node(p1.pid, sc1)
                        self.add_edge(node1, node2, pipe='1', label='pipe')

                # discard previous writes which have been consumed
                while read_nr > 0:
                    if wleft == 0:
                        wleft = writes[0][1]
                    nr = min([wleft, read_nr])
                    pipe_buf -= nr
                    read_nr -= nr
                    wleft -= nr
                    if wleft == 0:
                        writes.popleft()

                ri += 1

    def _dependency_signal(self):
        """ADD HB dependencies due to signal send/receive (cookies)"""
        for send, recv in self.session.cookie_e.values():
            proc1 = self.session.events[send.index].proc
            cnt1 = send.syscnt
            sender = self.make_node(proc1.pid, cnt1)

            proc2 = self.session.events[recv.index].proc
            cnt2 = recv.syscnt
            receiver = self.make_node(proc2.pid, cnt2)

            self.add_edge(sender, receiver, signal='1', label='signal')

    def _dependency_reparent(self):
        """Add HB dependencies due to reparenting of orphans to init"""

        def parent_pid(self, index):
            return self.session.events[index].proc.ppid

        for index in self.session.exit_e:

            # for each exit() syscall, get all the events that belong
            # to this syscall, and filter only the EventResource that
            # refer to ppid resources: the event.desc field of these
            # indicates the current children that will be reparented.

            ppid = parent_pid(index)
            if not ppid:
                continue

            # now that we know the children that are being reparented,
            # we add HB edges to the graph from a this syscall to
            # their own exit syscall.
            # FIXME1: to be precise, the edge needs to go to the next
            # access to the reaprent child's ppid, but this should be
            # close enough.
            # FIXME2: we assume that reparenting occurs to init; but
            # children of threads will first be reparented to another
            # thread if exists; this will need to be fixed.

            p1, cnt1 = self.session.s_ev_to_proc(self.session.events[index],
                                                 syscnt=True)
            node1 = self.make_node(p1.pid, cnt1)

            p2 = self.session.process_map[ppid]
            i2 = p2.sysind               # points to last syscall: exit
            cnt2 = p2.events[self.session.events[i2].pindex].syscnt
            node2 = self.make_node(p2.pid, cnt2)
            self.add_edge(node1, node2, reparent='1', label='reparent')


    def compute_vclocks(self, resources=False):
        """Compute the vector-clocks of nodes in the execution graph.
        @resources: if True, consider dependencies induces by resources
        """
        vclocks = dict()
        vclocks[self.session.process_map[1], 0] = VectorClock(1)

        for node in networkx.algorithms.dag.topological_sort(self):
            proc, index = self.split_node(node)
            vc = vclocks[(proc, index)]
            tick = False

            for nn in self.neighbors(node):
                next, ncnt = self.split_node(nn)

                # disregard resource dependencies if not @resource ?
                if not resources and 'resource' in self.edge[node][nn]:
                    continue

                # need to creat vclock for this node ?
                if (next, ncnt) not in vclocks:
                    vclocks[(next, ncnt)] = VectorClock(next.pid, vc)
                else:
                    vclocks[(next, ncnt)].merge(vc)

                # is this an edge that should cause a tick ?
                if next.pid != proc.pid:
                    if 'fork' in self.edge[node][nn]:
                        tick = True
                    elif 'signal' in self.edge[node][nn]:
                        tick = True
                    elif resources and 'resource' in self.edge[node][nn]:
                        tick = True
                else:
                    # remember for below
                    tproc = next
                    tcnt = ncnt

            if tick:
                # tick before the merge, but w/o effect on @vc
                vctmp = VectorClock(proc.pid, vc)
                vctmp.tick(proc.pid)
                vclocks[(tproc, tcnt)].merge(vctmp)

        self.vclocks = vclocks

    def crosscut_graph(self, anchors):
        """Given a list of initial nodes in the graph, find a consistent
        crosscut, such that both nodes are just about to be executed.
        Returns bookmarks dict of the cut, or None if none found
        @graph: graph data
        @vclock: vector vclocks
        @anchors: list of (graph) nodes
        """
        # YJF: improved version
        # FIXME: (1) should just merge syscnt and vector clock.
        #        (2) should create special nodes to represent process
        #            start and exit.  these nodes are not connected to
        #            nodes in other processes

        # if any of the anchors HB another anchor - we're screwed
        for n1, n2 in combinations(anchors, 2):
            p1, c1 = self.split_node(n1)
            p2, c2 = self.split_node(n2)
            assert not self.vclocks[(p1, c1)].race(self.vclocks[(p1, c1)]), \
                'Anchor nodes inconsistency: %s vs %s !' % (n1, n2)

        # @ticks will map from a <proc, clock> tuple to the first
        # syscall (syscnt) by which proc that value of local clock.
        #
        # We deliberately include in the map syscnt=0 which doesn't really
        # map to a real system call, because it doesn't help special case
        # it here: we have to deal with clone() and clone() returns anyway
        #
        # Only compute once and cache it inside vclock['ticks']...
        if 'ticks' in self.vclocks:
            ticks = self.vclocks['ticks']
        else:
            ticks = dict()
            for (proc, syscnt), vc in self.vclocks.iteritems():
                c = vc.get(proc.pid)
                if (proc, c) in ticks:  # use earlier ones
                    ticks[(proc, c)] = min(syscnt, ticks[(proc, c)])
                else:
                    ticks[(proc, c)] = syscnt
            self.vclocks['ticks'] = ticks

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

        vc = VectorClock()  # vector clocks for anchors
        for n in anchors:
            proc, cnt = self.split_node(n)
            assert cnt > 0, 'Race before process fork (%d:%d)' % \
                (proc.pid, cnt)
            vc.merge(self.vclocks[(proc, cnt)])
            logging.debug('    vc: %s' % self.vclocks[(proc, cnt)])

        logging.debug('merged clocks %s' % vc.clocks)
        logging.debug('ticks array %s' %
                      ([(p.pid, c, s) for ((p, c), s) in ticks.items()]))

        # syscnt before which we cut
        cut = dict([(int(p), int(c)) for p, c in
                    [n.split(':') for n in anchors]])

        for proc in self.session.process_list:
            if proc.pid in cut:
                continue

            # find the last time we heard from pid
            pid = proc.pid
            c = vc.get(pid)

            logging.debug("pid=%d, local clock=%d" % (pid, c))

            if (proc, c + 1) in ticks:
                # normal case: stop before the syscall
                syscnt = ticks[(proc, c + 1)]
            else:
                # special case: process already exited
                assert (c > 0), 'Invalid syscall count %d' % c
                syscnt = sys.maxint # use maxint to represent exited process

            cut[pid] = syscnt

        logging.debug('temp-cut: %s' % cut)
        # convert cut to bookmarks understandable by save_events()
        # we use two passes (first cut, then marks) because when checking
        # if a child process has been cloned or not, we must make sure
        # that we have computed the cut
        marks = dict()
        for pid, cnt in cut.iteritems():
            if cnt == sys.maxint:
                marks[pid] = 0 # include everything for already exited process
                continue
            if cnt > 0:
                marks[pid] = -cnt # normal case: negate to indicate cut before
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

            assert cnt == 0, 'invalid syscnt!'
            n = self.make_node(pid, 0)
            pred = self.predecessors(n)
            assert pred, "only the first process %d? can't have race!" % pid
            assert len(pred)>0, 'More than one parent for %d !' % pid

            prvproc, prvcnt = self.split_node(pred[0])

            logging.debug('parent %d, child %d, clone@%d, cut@%d' 
                          % (prvproc.pid, pid, prvcnt, cut[prvproc.pid]))

            if cut[prvproc.pid] <= prvcnt: # clone() not in cut
                logging.debug('exclude child not yet cloned')
            else: # clone() in cut
                logging.debug("include child already cloned")
                marks[pid] = -1 # -1 to include clone ret in bookmarks

        logging.debug('found cut: %s' % marks)
        return marks
